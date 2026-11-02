// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml.demo;

import com.iyasec.saml.Caught;
import com.iyasec.saml.Json;
import com.iyasec.saml.SamlError;
import com.iyasec.saml.SamlLogin;
import com.iyasec.saml.ServiceProvider;
import com.iyasec.saml.ssf.Events;
import com.iyasec.saml.ssf.SignalEvent;
import com.iyasec.saml.ssf.SignalsReceiver;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The demo: a server-rendered application that signs people in with SAML 2.0.
 * GET /healthz returns 200 and the body ok, before the identity provider is reachable.
 * GET /live-status is JSON and does not need an account id: whether any local account
 * session exists, the subject, the receiver state, and the accepted events (type and jti).
 */
public final class Demo {
    private static final Pattern ACCOUNT = Pattern.compile("^/u/([A-Za-z0-9_-]{6,32})(/.*)?$");
    private static final DateTimeFormatter INSTANT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter LOGGED_AT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'.000Z'").withZone(ZoneOffset.UTC);
    private static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "::1");
    private static final List<String> BINDINGS = List.of("post", "redirect", "artifact");
    private static final Map<String, String> BINDING_LABEL = Map.of(
        "post", "HTTP-POST", "redirect", "HTTP-Redirect", "artifact", "HTTP-Artifact");
    private static final int SESSION_MS = 8 * 3600_000;
    private static final int MAX_SESSIONS = 10_000;
    private static final int MAX_BODY = 512 * 1024;
    private static final int LOG_SIZE = 25;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Demo() {}

    public static void main(String[] args) throws Exception {
        Options options;
        try {
            options = Options.parse(args);
        } catch (IllegalArgumentException err) {
            Caught.error(err);
            System.err.println(err.getMessage());
            System.exit(1);
            return;
        }
        App app = new App(options);
        app.serve();
    }

    static final class Options {
        final int port;
        final String publicUrl;
        final boolean publicUrlGiven;
        final Path config;

        Options(int port, String publicUrl, boolean publicUrlGiven, Path config) {
            this.port = port;
            this.publicUrl = publicUrl;
            this.publicUrlGiven = publicUrlGiven;
            this.config = config;
        }

        static Options parse(String[] argv) {
            String publicUrl = System.getenv("PUBLIC_URL");
            boolean given = publicUrl != null && !publicUrl.isEmpty();
            String config = System.getenv("SAML_CONFIG");
            int index = 0;
            while (index < argv.length) {
                String arg = argv[index];
                if ("--public-url".equals(arg)) {
                    if (index + 1 >= argv.length) throw new IllegalArgumentException("--public-url needs a value");
                    publicUrl = argv[index + 1];
                    given = true;
                    index += 2;
                    continue;
                }
                if ("--config".equals(arg)) {
                    if (index + 1 >= argv.length) throw new IllegalArgumentException("--config needs a value");
                    config = argv[index + 1];
                    index += 2;
                    continue;
                }
                throw new IllegalArgumentException("Unknown argument " + arg);
            }
            if (given && (publicUrl == null || publicUrl.isBlank())) throw new IllegalArgumentException("--public-url is empty");
            if (publicUrl != null) publicUrl = publicUrl.replaceAll("/+$", "");
            int port = 3000;
            String rawPort = System.getenv("PORT");
            if (rawPort != null && !rawPort.isBlank()) port = Integer.parseInt(rawPort.trim());
            Path path = config == null || config.isBlank() ? Path.of("demo", "saml.json") : Path.of(config);
            return new Options(port, publicUrl, given, path.toAbsolutePath());
        }
    }

    static final class Session {
        final SamlLogin login;
        final String account;
        long expires;
        String setId;
        final List<Map<String, Object>> signals = new ArrayList<>();

        Session(SamlLogin login, String account, long expires, String setId) {
            this.login = login;
            this.account = account;
            this.expires = expires;
            this.setId = setId;
        }
    }

    static final class Held {
        final String sid;
        final Session session;

        Held(String sid, Session session) {
            this.sid = sid;
            this.session = session;
        }
    }

    static final class Stream {
        final OutputStream out;
        final Object writeLock = new Object();
        final Object gate = new Object();
        volatile boolean closed;

        Stream(OutputStream out) { this.out = out; }

        void write(String text) throws IOException {
            synchronized (writeLock) {
                if (closed) return;
                out.write(text.getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        }

        void close() {
            synchronized (gate) {
                closed = true;
                gate.notifyAll();
            }
        }

        boolean waitClosed(long millis) throws InterruptedException {
            synchronized (gate) {
                if (closed) return true;
                gate.wait(millis);
                return closed;
            }
        }
    }

    static final class App {
        final Options options;
        final byte[] secret;
        final byte[] styles;
        final byte[] appJs;
        final Map<String, Object> file;
        final boolean signalsOff;
        final Map<String, Object> ssf;
        final Object state = new Object();
        final Map<String, Session> sessions = new LinkedHashMap<>();
        final Map<String, List<String>> accountSets = new LinkedHashMap<>();
        final Map<String, Set<Stream>> listeners = new LinkedHashMap<>();
        final Map<String, String> verificationsAsked = new LinkedHashMap<>();
        ServiceProvider provider;
        volatile SignalsReceiver receiver;
        volatile String receiverState;
        final List<Map<String, String>> liveEvents = new CopyOnWriteArrayList<>();
        Map<String, Object> streamStatus;
        int sequence;
        boolean secureCookies = true;

        App(Options options) throws IOException {
            this.options = options;
            String sessionSecret = System.getenv("SESSION_SECRET");
            this.secret = sessionSecret != null && !sessionSecret.isEmpty()
                ? sessionSecret.getBytes(StandardCharsets.UTF_8) : random(32);
            Path here = Path.of("demo");
            this.styles = Files.readAllBytes(here.resolve("public").resolve("styles.css"));
            this.appJs = Files.readAllBytes(here.resolve("public").resolve("app.js"));
            this.file = readFile();
            this.signalsOff = Boolean.FALSE.equals(file.get("signals"));
            Map<String, Object> block = asMap(file.get("ssf"));
            Object transmitter = block == null ? null : block.get("transmitter");
            this.ssf = signalsOff || !(transmitter instanceof String text) || text.isBlank() ? null : block;
            this.receiverState = signalsOff
                ? "not configured (signals are off)"
                : ssf != null ? "starting" : "not configured (no ssf block in the configuration file)";
        }

        void serve() throws IOException {
            secureFromConfig();
            HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", options.port), 0);
            server.createContext("/", this::handle);
            server.setExecutor(Executors.newCachedThreadPool(runnable -> {
                Thread thread = new Thread(runnable, "saml2-sp-demo");
                thread.setDaemon(true);
                return thread;
            }));
            server.start();
            System.out.println("saml2-sp demo on port " + options.port + ", configuration " + options.config);
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                if (receiver != null) receiver.stop();
                server.stop(0);
            }));
            try {
                Thread.currentThread().join();
            } catch (InterruptedException ignored) {
                Caught.error(ignored);
                Thread.currentThread().interrupt();
                if (receiver != null) receiver.stop();
                server.stop(0);
            }
        }

        void handle(HttpExchange exchange) {
            boolean[] started = {false};
            try {
                route(exchange, started);
            } catch (Exception err) {
                Caught.error(err);
                System.out.println(err);
                if (!started[0]) {
                    try {
                        send(exchange, 500, page("Error", "<h1>Something went wrong</h1><p class=\"problem\">" + esc(messageOf(err)) + "</p><p><a href=\"/\">Home</a></p>").getBytes(StandardCharsets.UTF_8), null, null, started);
                    } catch (Exception ignored) {
                        Caught.error(ignored);
                        exchange.close();
                    }
                }
            }
        }

        void route(HttpExchange exchange, boolean[] started) throws Exception {
            String method = exchange.getRequestMethod();
            URI uri = exchange.getRequestURI();
            String path = uri.getPath() == null ? "/" : uri.getPath();
            Map<String, List<String>> query = query(uri.getRawQuery());
            System.err.println(exchange.getRemoteAddress() + " - \"" + method + " " + path + "\"");
            if ("/healthz".equals(path)) {
                send(exchange, 200, "ok".getBytes(StandardCharsets.UTF_8), Map.of("content-type", "text/plain"), null, started);
                return;
            }
            if ("/live-status".equals(path) && "GET".equals(method)) {
                liveStatus(exchange, started);
                return;
            }
            if ("/styles.css".equals(path)) {
                send(exchange, 200, styles, Map.of("content-type", "text/css; charset=utf-8", "cache-control", "max-age=300"), null, started);
                return;
            }
            if ("/app.js".equals(path)) {
                send(exchange, 200, appJs, Map.of("content-type", "text/javascript; charset=utf-8", "cache-control", "max-age=300"), null, started);
                return;
            }
            Matcher scoped = ACCOUNT.matcher(path);
            Held here = scoped.matches() ? accountOf(cookieHeader(exchange), scoped.group(1)) : null;
            String sub = scoped.matches() ? (scoped.group(2) == null || scoped.group(2).isEmpty() ? "/" : scoped.group(2)) : null;
            if (scoped.matches() && here == null) {
                if ("/api/signals".equals(sub)) {
                    send(exchange, 401, Json.stringify(Map.of("signedIn", false)).getBytes(StandardCharsets.UTF_8),
                        Map.of("content-type", "application/json", "cache-control", "no-store"), null, started);
                    return;
                }
                if ("/events".equals(sub)) {
                    send(exchange, 204, new byte[0], null, null, started);
                    return;
                }
                redirect(exchange, "/?gone=1", 303, null, started);
                return;
            }
            if (here != null && "/events".equals(sub) && "GET".equals(method)) {
                events(exchange, here, query, started);
                return;
            }
            if (here != null && "/api/signals".equals(sub) && "GET".equals(method)) {
                int after = number(first(query, "after"), 0);
                List<Map<String, Object>> events;
                int last;
                Map<String, Object> status;
                synchronized (state) {
                    events = new ArrayList<>();
                    for (int index = here.session.signals.size() - 1; index >= 0; index--) {
                        Map<String, Object> item = here.session.signals.get(index);
                        if (((Number) item.get("id")).intValue() > after) events.add(item);
                    }
                    last = here.session.signals.isEmpty() ? after : ((Number) here.session.signals.get(0).get("id")).intValue();
                    status = streamStatus;
                }
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("signedIn", true);
                body.put("events", events);
                body.put("lastId", last);
                body.put("streamStatus", status);
                send(exchange, 200, Json.stringify(body).getBytes(StandardCharsets.UTF_8),
                    Map.of("content-type", "application/json", "cache-control", "no-store"), null, started);
                return;
            }
            if ("/".equals(path) && "GET".equals(method)) {
                List<Held> first = accountsOfSet(cookies(exchange).get("aset"));
                if (!first.isEmpty()) {
                    String gone = query.containsKey("gone") ? "?gone=1" : "";
                    redirect(exchange, "/u/" + first.get(0).session.account + "/" + gone, 303, null, started);
                    return;
                }
            }
            if ("GET".equals(method) && ("/".equals(path) || (here != null && "/".equals(sub)))) {
                Session session = here == null ? null : here.session;
                String problem = null;
                ServiceProvider sp = null;
                try {
                    sp = serviceProvider();
                } catch (Exception err) {
                    Caught.error(err);
                    dropProvider();
                    problem = "The service provider is not configured yet: " + messageOf(err) + ". Run the setup script (python scripts/configure_iya_sts.py).";
                }
                String tab = "events".equals(first(query, "tab")) ? "events" : "identity";
                String verify = first(query, "verify");
                String notice = "sent".equals(verify) ? "Verification event requested; it shows in the log within a few seconds."
                    : "failed".equals(verify) ? "The identity provider refused the verification request; see the demo's log." : null;
                String gone = query.containsKey("gone") ? "The account you opened is no longer signed in here." : null;
                Map<String, String> headers = new LinkedHashMap<>();
                if (session != null) {
                    headers.put("content-security-policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
                }
                String shown = gone != null && session == null ? gone : problem;
                send(exchange, 200, home(session, sp, shown, tab, notice, accountsOfSet(cookies(exchange).get("aset")), gone).getBytes(StandardCharsets.UTF_8), headers, null, started);
                return;
            }
            if ("/saml/metadata".equals(path) && "GET".equals(method)) {
                ServiceProvider sp;
                try {
                    sp = serviceProvider();
                } catch (Exception err) {
                    Caught.error(err);
                    dropProvider();
                    throw err;
                }
                send(exchange, 200, sp.metadata().getBytes(StandardCharsets.UTF_8), Map.of("content-type", "application/samlmetadata+xml"), null, started);
                return;
            }
            if ("/login".equals(path) && "GET".equals(method)) {
                login(exchange, query, started);
                return;
            }
            if ("/saml/acs".equals(path) && ("GET".equals(method) || "POST".equals(method))) {
                acs(exchange, path, uri.getRawQuery(), started);
                return;
            }
            if (here != null && "/signals/verify".equals(sub) && "POST".equals(method)) {
                verify(exchange, here, started);
                return;
            }
            if (here != null && "/signals/clear".equals(sub) && "POST".equals(method)) {
                synchronized (state) { here.session.signals.clear(); }
                redirect(exchange, "/u/" + here.session.account + "/?tab=events", 303, null, started);
                return;
            }
            if (here != null && "/logout".equals(sub) && "POST".equals(method)) {
                synchronized (state) { endSession(here.sid); }
                if (receiver != null) receiver.untrack(here.sid);
                tell(here.sid, "signed-out", Map.of());
                redirect(exchange, "/", 303, null, started);
                return;
            }
            if ("/logout".equals(path) && "POST".equals(method)) {
                List<Held> all = accountsOfSet(cookies(exchange).get("aset"));
                for (Held item : all) {
                    synchronized (state) { endSession(item.sid); }
                    if (receiver != null) receiver.untrack(item.sid);
                    tell(item.sid, "signed-out", Map.of());
                }
                redirect(exchange, "/", 303, List.of(cookie("aset", "", "/", 0, "Lax")), started);
                return;
            }
            send(exchange, 404, page("Not found", "<h1>Not found</h1>").getBytes(StandardCharsets.UTF_8), null, null, started);
        }

        void liveStatus(HttpExchange exchange, boolean[] started) throws IOException {
            boolean signedIn = false;
            String subject = null;
            long now = System.currentTimeMillis();
            synchronized (state) {
                for (Session session : sessions.values()) {
                    if (session.expires <= now) continue;
                    signedIn = true;
                    String name = session.login.nameId;
                    if (subject == null && name != null && !name.isEmpty()) subject = name;
                }
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("signedIn", signedIn);
            body.put("subject", subject);
            body.put("receiver", receiverState == null ? "" : receiverState);
            body.put("events", new ArrayList<>(liveEvents));
            send(exchange, 200, Json.stringify(body).getBytes(StandardCharsets.UTF_8),
                Map.of("content-type", "application/json"), null, started);
        }

        void events(HttpExchange exchange, Held here, Map<String, List<String>> query, boolean[] started) throws Exception {
            started[0] = true;
            Headers headers = exchange.getResponseHeaders();
            headers.set("Content-Type", "text/event-stream");
            headers.set("Cache-Control", "no-store");
            headers.set("X-Accel-Buffering", "no");
            exchange.sendResponseHeaders(200, 0);
            String afterHeader = exchange.getRequestHeaders().getFirst("Last-Event-ID");
            int after = number(afterHeader != null ? afterHeader : first(query, "after"), 0);
            Stream stream = new Stream(exchange.getResponseBody());
            try {
                stream.write("retry: 2000\n\n");
                List<Map<String, Object>> replay = new ArrayList<>();
                Map<String, Object> status;
                synchronized (state) {
                    for (int index = here.session.signals.size() - 1; index >= 0; index--) {
                        Map<String, Object> item = here.session.signals.get(index);
                        if (((Number) item.get("id")).intValue() > after) replay.add(item);
                    }
                    status = streamStatus == null ? null : new LinkedHashMap<>(streamStatus);
                    listeners.computeIfAbsent(here.sid, key -> new java.util.LinkedHashSet<>()).add(stream);
                }
                for (Map<String, Object> entry : replay) {
                    stream.write("id: " + entry.get("id") + "\nevent: signal\ndata: " + Json.stringify(entry) + "\n\n");
                }
                if (status != null) stream.write("event: stream\ndata: " + Json.stringify(status) + "\n\n");
                while (!stream.waitClosed(20_000)) stream.write(": keep-alive\n\n");
            } catch (Exception err) {
                Caught.error(err);
                stream.close();
            } finally {
                synchronized (state) {
                    Set<Stream> found = listeners.get(here.sid);
                    if (found != null) {
                        found.remove(stream);
                        if (found.isEmpty()) listeners.remove(here.sid);
                    }
                }
                exchange.close();
            }
        }

        void login(HttpExchange exchange, Map<String, List<String>> query, boolean[] started) throws Exception {
            ServiceProvider sp = serviceProvider();
            String asked = first(query, "binding");
            String responseBinding = asked != null && BINDINGS.contains(asked) ? asked : null;
            String nonce = Base64.getEncoder().encodeToString(random(16));
            Held again = query.containsKey("account") ? accountOf(cookieHeader(exchange), first(query, "account")) : null;
            boolean add = "1".equals(first(query, "add"));
            var options = new com.iyasec.saml.LoginOptions();
            options.relayState = "/";
            options.nonce = nonce;
            options.responseBinding = responseBinding;
            options.forceAuthn = add || again != null;
            if (again != null) {
                options.subjectHint = again.session.login.nameId;
                options.subjectHintFormat = again.session.login.nameIdFormat == null || again.session.login.nameIdFormat.isEmpty()
                    ? null : again.session.login.nameIdFormat;
            }
            var request = sp.login(options);
            Map<String, String> jar = cookies(exchange);
            List<String> before = new ArrayList<>();
            Object pendingRaw = unseal(jar.get("saml_pending"));
            Map<String, Object> previous = asMap(pendingRaw);
            if (previous != null && previous.get("ids") instanceof List<?> ids) {
                for (Object id : ids) if (id != null) before.add(String.valueOf(id));
            }
            List<String> ids = new ArrayList<>();
            ids.add(request.id);
            ids.addAll(before);
            if (ids.size() > 3) ids = new ArrayList<>(ids.subList(0, 3));
            Map<String, Object> pendingBody = new LinkedHashMap<>();
            pendingBody.put("ids", ids);
            String setNow = jar.get("aset");
            synchronized (state) {
                if (setNow != null && accountSets.containsKey(setNow)) pendingBody.put("set", setNow);
            }
            String acsPath = acsPath(sp);
            String pending = cookie("saml_pending", sealed(pendingBody), acsPath, 600, "None");
            if ("redirect".equals(request.binding)) {
                redirect(exchange, request.url, 302, List.of(pending), started);
                return;
            }
            URI origin = URI.create(request.url);
            String formAction = origin.getScheme() + "://" + origin.getRawAuthority();
            send(exchange, 200, request.html.getBytes(StandardCharsets.UTF_8), Map.of(
                "content-security-policy", "default-src 'none'; script-src 'nonce-" + nonce + "'; form-action " + formAction + "; frame-ancestors 'none'; base-uri 'none'"
            ), List.of(pending), started);
        }

        void acs(HttpExchange exchange, String path, String rawQuery, boolean[] started) throws Exception {
            ServiceProvider sp = serviceProvider();
            String body = "POST".equals(exchange.getRequestMethod()) ? readBody(exchange) : null;
            String url = rawQuery == null || rawQuery.isEmpty() ? path : path + "?" + rawQuery;
            Object pendingRaw = unseal(cookies(exchange).get("saml_pending"));
            Map<String, Object> pending = asMap(pendingRaw);
            if (pending == null) pending = Map.of();
            String clear = cookie("saml_pending", "", acsPath(sp), 0, "None");
            try {
                SamlLogin login = sp.acs(exchange.getRequestMethod(), url, body, pending.get("ids"));
                long now = System.currentTimeMillis();
                synchronized (state) {
                    if (sessions.size() >= MAX_SESSIONS) {
                        List<String> expired = new ArrayList<>();
                        sessions.forEach((key, value) -> { if (value.expires <= now) expired.add(key); });
                        expired.forEach(sessions::remove);
                    }
                    if (sessions.size() >= MAX_SESSIONS) throw new IllegalStateException("too many sessions");
                }
                String sid = b64(random(32));
                long cap = login.sessionNotOnOrAfter == null ? Long.MAX_VALUE : login.sessionNotOnOrAfter.toEpochMilli();
                long until = Math.min(now + SESSION_MS, cap);
                String oldSet = pending.get("set") instanceof String text && !text.isEmpty() ? text : cookies(exchange).get("aset");
                List<Held> accounts = accountsOfSet(oldSet);
                Held existing = null;
                for (Held item : accounts) {
                    if (samePerson(item.session.login, login)) { existing = item; break; }
                }
                String account = existing != null ? existing.session.account : b64(random(9));
                if (existing != null) {
                    synchronized (state) { endSession(existing.sid); }
                    if (receiver != null) receiver.untrack(existing.sid);
                    tell(existing.sid, "replaced", Map.of());
                }
                String setId = b64(random(32));
                List<String> order = new ArrayList<>();
                for (Held item : accounts) order.add(existing != null && item.sid.equals(existing.sid) ? sid : item.sid);
                if (existing == null) order.add(sid);
                synchronized (state) {
                    if (oldSet != null) accountSets.remove(oldSet);
                    accountSets.put(setId, order);
                    for (String item : order) {
                        if (!item.equals(sid) && sessions.containsKey(item)) sessions.get(item).setId = setId;
                    }
                    sessions.put(sid, new Session(login, account, until, setId));
                }
                if (receiver != null) receiver.track(sid, login, Instant.ofEpochMilli(until));
                System.out.println("signed in " + login.nameId + " by " + login.binding + " (assertion " + login.assertionId + "); " + order.size() + " account(s) in this browser");
                long longest = until;
                synchronized (state) {
                    for (String item : order) if (sessions.containsKey(item)) longest = Math.max(longest, sessions.get(item).expires);
                }
                int maxAge = (int) Math.max(0, (longest - now) / 1000);
                redirect(exchange, "/u/" + account + "/", 303, List.of(clear, cookie("aset", setId, "/", maxAge, "Lax")), started);
            } catch (Exception err) {
                Caught.error(err);
                String what = err instanceof SamlError saml ? saml.code + ": " + saml.getMessage() : String.valueOf(err.getMessage() == null ? err : err.getMessage());
                System.out.println("sign-in refused: " + what);
                send(exchange, 400, page("Sign-in failed", "<h1>Sign-in failed</h1><p class=\"problem\">" + esc(what) + "</p><p><a href=\"/\">Start again</a></p>").getBytes(StandardCharsets.UTF_8),
                    null, List.of(clear), started);
            }
        }

        void verify(HttpExchange exchange, Held here, boolean[] started) throws Exception {
            String outcome = "failed";
            SignalsReceiver current = receiver;
            if (current != null && current.stream() != null) {
                try {
                    String token = b64(random(12));
                    synchronized (state) {
                        verificationsAsked.put(token, here.sid);
                        if (verificationsAsked.size() > 1000) verificationsAsked.remove(verificationsAsked.keySet().iterator().next());
                    }
                    current.verify(token);
                    outcome = "sent";
                } catch (Exception err) {
                    Caught.error(err);
                    System.out.println("ssf: verification request refused: " + messageOf(err));
                }
            }
            String accept = exchange.getRequestHeaders().getFirst("Accept");
            if (accept != null && accept.contains("application/json")) {
                send(exchange, "sent".equals(outcome) ? 202 : 502, Json.stringify(Map.of("outcome", outcome)).getBytes(StandardCharsets.UTF_8),
                    Map.of("content-type", "application/json", "cache-control", "no-store"), null, started);
                return;
            }
            redirect(exchange, "/u/" + here.session.account + "/?tab=events&verify=" + outcome, 303, null, started);
        }

        ServiceProvider serviceProvider() {
            synchronized (state) {
                if (provider == null) {
                    provider = ServiceProvider.fromFile(options.config.toString(), portOverrides(), null);
                    startReceiver(provider);
                }
                return provider;
            }
        }

        void dropProvider() {
            synchronized (state) { provider = null; }
        }

        void startReceiver(ServiceProvider sp) {
            if (Boolean.FALSE.equals(sp.config.signals)) {
                receiverState = "not configured (signals are off)";
                return;
            }
            if (ssf == null || receiver != null) return;
            Map<String, String> tls = new LinkedHashMap<>();
            if (sp.config.idpCa != null) tls.put("ca", sp.config.idpCa);
            tls.put("cert", sp.config.certificatePem);
            tls.put("key", sp.config.privateKeyPem);
            int interval = 5000;
            if (ssf.get("pollIntervalMs") instanceof Number number && number.intValue() != 0) interval = number.intValue();
            SignalsReceiver built = new SignalsReceiver(String.valueOf(ssf.get("transmitter")), (ids, event) -> {
                Object reason = null;
                if (event.payload != null) {
                    if (event.payload.containsKey("reason_user") && event.payload.get("reason_user") != null) reason = event.payload.get("reason_user");
                    else if (event.payload.containsKey("reason_admin")) reason = event.payload.get("reason_admin");
                    else reason = event.payload.get("reason");
                }
                for (String sid : ids) {
                    synchronized (state) { endSession(sid); }
                    Map<String, Object> data = new LinkedHashMap<>();
                    data.put("type", shortType(event.type));
                    data.put("reason", reason);
                    tell(sid, "signed-out", data);
                }
                System.out.println("ssf: " + shortType(event.type) + " ended " + ids.size() + " local session(s)");
            }).tls(tls).description("saml2-sp demo (" + sp.config.entityId + ")").pollIntervalMs(interval);
            built.on("*", this::onEvent);
            receiver = built;
            Thread thread = new Thread(() -> {
                try {
                    built.start();
                    Map<String, Object> stream = built.stream();
                    Object id = stream == null ? null : stream.get("stream_id");
                    receiverState = "polling stream " + id + " at " + ssf.get("transmitter");
                } catch (Exception err) {
                    Caught.error(err);
                    receiverState = "not running: " + messageOf(err);
                    if (receiver == built) receiver = null;
                    System.out.println("ssf: the receiver did not start: " + messageOf(err));
                }
            }, "saml2-sp-ssf-start");
            thread.setDaemon(true);
            thread.start();
        }

        void onEvent(SignalEvent event) {
            Map<String, String> seen = new LinkedHashMap<>();
            seen.put("type", event.type == null ? "" : event.type);
            seen.put("jti", event.jti == null ? "" : event.jti);
            liveEvents.add(seen);
            int id;
            synchronized (state) { id = ++sequence; }
            Map<String, String> subject = event.subject == null ? Map.of() : event.subject;
            List<String> parts = new ArrayList<>();
            if (subject.get("person") != null) parts.add(subject.get("person"));
            if (subject.get("email") != null) parts.add(subject.get("email"));
            if (subject.get("idpSession") != null) parts.add("IdP session " + subject.get("idpSession"));
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("id", id);
            entry.put("at", LOGGED_AT.format(Instant.now()));
            entry.put("type", event.type);
            entry.put("family", familyOf(event.type));
            entry.put("ended", event.ended);
            entry.put("about", "session");
            entry.put("subject", String.join(", ", parts));
            entry.put("members", event.payload == null ? Map.of() : event.payload);
            entry.put("jti", event.jti);
            if (Events.EVENT.get("verification").equals(event.type)) {
                String token = String.valueOf(event.payload == null || event.payload.get("state") == null ? "" : event.payload.get("state"));
                String asker;
                synchronized (state) { asker = verificationsAsked.remove(token); }
                if (asker != null) {
                    entry.put("about", "stream");
                    logFor(asker, entry);
                }
                System.out.println("ssf: verification received" + (asker == null ? " (asked by no session here)" : ""));
                return;
            }
            if (Events.EVENT.get("stream_updated").equals(event.type)) {
                Map<String, Object> status = new LinkedHashMap<>();
                status.put("status", String.valueOf(event.payload == null || event.payload.get("status") == null ? "" : event.payload.get("status")));
                status.put("reason", event.payload == null ? null : event.payload.get("reason"));
                status.put("at", entry.get("at"));
                List<String> sids;
                synchronized (state) {
                    streamStatus = status;
                    sids = new ArrayList<>(listeners.keySet());
                }
                for (String sid : sids) tell(sid, "stream", status);
                return;
            }
            if (!event.ended) {
                for (String sid : event.sessions) logFor(sid, entry);
            }
            endUnmatchedRevocation(event);
        }

        /** iya-sts's CAEP session id is not the assertion SessionIndex, so a session-revoked event does not match this demo's one session. */
        void endUnmatchedRevocation(SignalEvent event) {
            if (!Events.EVENT.get("session_revoked").equals(event.type)) return;
            if (event.ended || (event.sessions != null && !event.sessions.isEmpty())) return;
            String caepSession = event.subject == null ? null : event.subject.get("idpSession");
            String sid;
            String sessionIndex;
            synchronized (state) {
                if (sessions.size() != 1) return;
                sid = sessions.keySet().iterator().next();
                Session found = sessions.get(sid);
                if (found == null) return;
                sessionIndex = found.login.sessionIndex;
            }
            if (java.util.Objects.equals(sessionIndex, caepSession)) return;
            synchronized (state) { endSession(sid); }
            if (receiver != null) receiver.untrack(sid);
            Object reason = null;
            if (event.payload != null) {
                if (event.payload.get("reason_user") != null) reason = event.payload.get("reason_user");
                else if (event.payload.containsKey("reason_admin")) reason = event.payload.get("reason_admin");
                else reason = event.payload.get("reason");
            }
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("type", shortType(event.type));
            data.put("reason", reason);
            tell(sid, "signed-out", data);
            System.out.println("ssf: the assertion SessionIndex is not the CAEP session id; ended this demo's one session");
        }

        void logFor(String sid, Map<String, Object> entry) {
            synchronized (state) {
                Session found = sessions.get(sid);
                if (found == null) return;
                found.signals.add(0, entry);
                if (found.signals.size() > LOG_SIZE) found.signals.subList(LOG_SIZE, found.signals.size()).clear();
            }
            tell(sid, "signal", entry, ((Number) entry.get("id")).intValue());
        }

        void tell(String sid, String event, Object data) { tell(sid, event, data, null); }

        void tell(String sid, String event, Object data, Integer eventId) {
            List<Stream> streams;
            synchronized (state) { streams = new ArrayList<>(listeners.getOrDefault(sid, Set.of())); }
            String prefix = eventId == null ? "" : "id: " + eventId + "\n";
            String text = prefix + "event: " + event + "\ndata: " + Json.stringify(data) + "\n\n";
            List<Stream> dead = new ArrayList<>();
            for (Stream stream : streams) {
                try {
                    stream.write(text);
                } catch (Exception err) {
                    Caught.error(err);
                    dead.add(stream);
                }
                if ("signed-out".equals(event)) stream.close();
            }
            synchronized (state) {
                Set<Stream> found = listeners.get(sid);
                if (found != null) {
                    found.removeAll(dead);
                    if ("signed-out".equals(event) || found.isEmpty()) listeners.remove(sid);
                }
            }
        }

        void endSession(String sid) {
            synchronized (state) {
                Session found = sessions.remove(sid);
                if (found == null) return;
                List<String> left = new ArrayList<>();
                for (String item : accountSets.getOrDefault(found.setId, List.of())) if (!item.equals(sid)) left.add(item);
                if (left.isEmpty()) accountSets.remove(found.setId);
                else accountSets.put(found.setId, left);
            }
        }

        List<Held> accountsOfSet(String setId) {
            List<Held> out = new ArrayList<>();
            List<String> expired = new ArrayList<>();
            long now = System.currentTimeMillis();
            synchronized (state) {
                for (String sid : new ArrayList<>(accountSets.getOrDefault(setId, List.of()))) {
                    Session found = sessions.get(sid);
                    if (found == null) continue;
                    if (found.expires <= now) {
                        endSession(sid);
                        expired.add(sid);
                        continue;
                    }
                    out.add(new Held(sid, found));
                }
            }
            for (String sid : expired) if (receiver != null) receiver.untrack(sid);
            return out;
        }

        Held accountOf(String header, String account) {
            if (account == null) return null;
            for (Held item : accountsOfSet(cookiesOf(header).get("aset"))) {
                if (account.equals(item.session.account)) return item;
            }
            return null;
        }

        Map<String, Object> portOverrides() {
            Map<String, Object> raw = readFile();
            String entity = raw.get("entityId") instanceof String text ? text : "";
            String acs = raw.get("acsUrl") instanceof String text ? text : "";
            Map<String, Object> out = new LinkedHashMap<>();
            if (entity.isEmpty() || acs.isEmpty()) return out;
            Map<String, String> ends = endpointsFor(entity, acs);
            if (ends.get("entityId") != null) out.put("entityId", ends.get("entityId"));
            if (ends.get("acsUrl") != null) out.put("acsUrl", ends.get("acsUrl"));
            return out;
        }

        Map<String, String> endpointsFor(String entityId, String acsUrl) {
            if (options.publicUrlGiven && options.publicUrl != null && !options.publicUrl.isEmpty()) {
                URI base = URI.create(options.publicUrl.endsWith("/") ? options.publicUrl : options.publicUrl + "/");
                return Map.of("entityId", move(entityId, base), "acsUrl", move(acsUrl, base));
            }
            return Map.of("entityId", onPort(entityId, options.port), "acsUrl", onPort(acsUrl, options.port));
        }

        void secureFromConfig() {
            try {
                String acs = portOverrides().getOrDefault("acsUrl", "http://localhost:" + options.port + "/").toString();
                URI uri = URI.create(acs);
                String host = uri.getHost();
                secureCookies = "https".equalsIgnoreCase(uri.getScheme()) || "localhost".equals(host) || "127.0.0.1".equals(host);
            } catch (Exception err) {
                Caught.error(err);
                System.out.println("cannot read " + options.config + ": " + messageOf(err));
            }
        }

        Map<String, Object> readFile() {
            try {
                Object parsed = Json.parse(Files.readString(options.config));
                Map<String, Object> object = asMap(parsed);
                return object == null ? Map.of() : object;
            } catch (IOException err) {
                Caught.error(err);
                return Map.of();
            }
        }

        String home(Session session, ServiceProvider sp, String problem, String tab, String notice, List<Held> accounts, String gone) {
            if (session != null) {
                String base = "/u/" + session.account;
                SamlLogin login = session.login;
                StringBuilder rows = new StringBuilder();
                login.attributes.forEach((name, values) -> {
                    String friendly = login.attributeFriendlyNames.get(name);
                    rows.append("<tr><th>").append(esc(friendly == null || friendly.isEmpty() ? name : friendly));
                    if (friendly != null && !friendly.isEmpty()) rows.append("<br><small>").append(esc(name)).append("</small>");
                    rows.append("</th><td>");
                    for (int index = 0; index < values.size(); index++) {
                        if (index > 0) rows.append("<br>");
                        rows.append(esc(values.get(index)));
                    }
                    rows.append("</td></tr>");
                });
                String instant = login.authnInstant == null ? "" : INSTANT.format(login.authnInstant);
                String encrypted = login.encrypted
                    ? "arrived encrypted (EncryptedAssertion), decrypted with this service provider's key"
                    : "arrived in clear";
                String identity = "<table class=\"facts\"><tr><th>NameID</th><td>" + esc(login.nameId) + "<br><small>" + esc(login.nameIdFormat)
                    + "</small></td></tr><tr><th>Identity provider</th><td>" + esc(login.issuer) + "</td></tr><tr><th>Response binding</th><td>"
                    + esc(BINDING_LABEL.getOrDefault(login.binding, login.binding == null ? "" : login.binding)) + "</td></tr><tr><th>Authenticated</th><td>"
                    + esc(instant) + "<br><small>" + esc(login.authnContextClassRef) + "</small></td></tr><tr><th>Session index</th><td>"
                    + esc(login.sessionIndex) + "</td></tr><tr><th>Assertion</th><td>" + esc(login.assertionId) + "<br><small>" + encrypted
                    + "; signature verified</small></td></tr></table><h2>Attributes</h2>"
                    + (rows.length() == 0 ? "<p>The identity provider released no attributes.</p>" : "<table class=\"facts\">" + rows + "</table>");
                int count = session.signals.size();
                int last = session.signals.isEmpty() ? 0 : ((Number) session.signals.get(0).get("id")).intValue();
                String panel = "events".equals(tab) ? eventsPanel(base, session, notice) : identity;
                String goneRow = gone == null ? "" : "<p class=\"notice\">" + esc(gone) + "</p>";
                return page("Signed in", "<h1>Signed in as " + esc(login.nameId) + "</h1>" + accountBar(accounts, session) + goneRow
                    + tabs(base, tab, count) + "<p id=\"signal-banner\" class=\"problem\" hidden></p><p id=\"signal-toast\" class=\"notice\" hidden></p>"
                    + "<div role=\"tabpanel\" id=\"panel\" data-base=\"" + base + "\" data-tab=\"" + tab + "\" data-last-id=\"" + last + "\">" + panel
                    + "</div><form method=\"post\" action=\"" + base + "/logout\" class=\"inline\"><button type=\"submit\">Sign out of this account</button></form><script src=\"/app.js\"></script>");
            }
            String requestBinding = "(configuration not loaded)";
            String entity = "the identity provider";
            if (sp != null) {
                requestBinding = "post".equals(sp.config.requestBinding) ? "HTTP-POST" : "HTTP-Redirect";
                entity = sp.idp().entityId;
            }
            StringBuilder buttons = new StringBuilder();
            for (String binding : BINDINGS) {
                String primary = sp != null && binding.equals(sp.config.responseBinding) ? " primary" : "";
                buttons.append("<a class=\"button").append(primary).append("\" href=\"/login?binding=").append(binding)
                    .append("\">Sign in — response by ").append(BINDING_LABEL.get(binding)).append("</a>\n");
            }
            String problemRow = problem == null ? "" : "<p class=\"problem\">" + esc(problem) + "</p>";
            return page("Sign in", "<h1>Sign in with SAML 2.0</h1>" + problemRow
                + "<p>Service provider-initiated single sign-on: this application sends a <strong>signed</strong> AuthnRequest on <strong>"
                + esc(requestBinding) + "</strong> to " + esc(entity) + ", and asks for the Response on the binding you pick.</p>"
                + "<p class=\"buttons\">" + buttons + "</p><p><a href=\"/saml/metadata\">This service provider's metadata</a></p>");
        }

        String eventsPanel(String base, Session session, String notice) {
            Map<String, Object> stream = receiver == null ? null : receiver.stream();
            List<?> delivered = List.of();
            if (stream != null && stream.get("events_delivered") instanceof List<?> list) delivered = list;
            int lastId = session.signals.isEmpty() ? 0 : ((Number) session.signals.get(0).get("id")).intValue();
            String status = streamStatus == null ? "enabled" : streamStatus.get("status") + " (" + streamStatus.get("at") + ")";
            String streamRows = "";
            if (stream != null) {
                StringBuilder badges = new StringBuilder();
                for (Object item : delivered) {
                    String type = String.valueOf(item);
                    if (badges.length() > 0) badges.append("<br>");
                    badges.append("<span class=\"badge ").append(familyOf(type).toLowerCase(Locale.ROOT)).append("\">")
                        .append(familyOf(type)).append("</span> ").append(esc(shortType(type)));
                }
                if (badges.length() == 0) badges.append("(nothing yet)");
                Object delivery = stream.get("delivery");
                String endpoint = delivery instanceof Map<?, ?> map ? String.valueOf(map.get("endpoint_url")) : "";
                streamRows = "<tr><th>Stream</th><td>" + esc(stream.get("stream_id")) + "<br><small>poll delivery (RFC 8936) at " + esc(endpoint)
                    + "</small></td></tr><tr><th>Authentication</th><td>mutual TLS with this service provider's own certificate</td></tr>"
                    + "<tr><th>Delivers</th><td>" + badges + "</td></tr>";
            }
            String noticeRow = notice == null ? "" : "<p class=\"notice\">" + esc(notice) + "</p>";
            String verify = stream == null ? "" : "<form method=\"post\" action=\"" + base + "/signals/verify\" class=\"inline\" id=\"verify-form\"><button type=\"submit\">Request verification event</button></form>";
            StringBuilder items = new StringBuilder();
            for (Map<String, Object> item : session.signals) items.append(logItem(item));
            String emptyHidden = session.signals.isEmpty() ? "" : " hidden";
            return "<section class=\"card\"><h2>Shared Signals stream</h2>" + noticeRow + "<table class=\"facts\"><tr><th>Receiver</th><td>"
                + esc(receiverState) + "</td></tr><tr><th>Stream status</th><td id=\"stream-status\">" + esc(status) + "</td></tr>" + streamRows
                + "<tr><th>Ends this session on</th><td>session-revoked, account-disabled, account-purged, credential-compromise, sessions-revoked</td></tr></table>"
                + verify + "</section><section class=\"card\"><h2>Event log</h2><p><small>The CAEP and RISC events about this session or its person, newest first, and the verification events this session asked for. Each appears here within moments of the receiver getting it: <span id=\"live-state\">connecting…</span></small></p>"
                + "<ol class=\"log\" id=\"log\" data-last-id=\"" + lastId + "\">" + items + "</ol><p class=\"empty\" id=\"log-empty\"" + emptyHidden
                + ">No CAEP or RISC event about this session yet. At the identity provider, change this person's password (credential-change), sign them out (session-revoked), or disable them (account-disabled), and watch this tab.</p>"
                + "<form method=\"post\" action=\"" + base + "/signals/clear\" class=\"inline\"><button type=\"submit\" class=\"secondary\">Clear this session's log</button></form></section>";
        }

        String logItem(Map<String, Object> entry) {
            StringBuilder rows = new StringBuilder();
            Object members = entry.get("members");
            if (members instanceof Map<?, ?> map) {
                for (Map.Entry<?, ?> item : map.entrySet()) {
                    if ("subject".equals(String.valueOf(item.getKey()))) continue;
                    rows.append("<tr><th>").append(esc(item.getKey())).append("</th><td>").append(esc(member(item.getValue()))).append("</td></tr>");
                }
            }
            String about = "stream".equals(entry.get("about")) ? "about the stream: the verification this session asked for"
                : Boolean.TRUE.equals(entry.get("ended")) ? "ended this session" : "recorded; this session continues";
            String subject = entry.get("subject") == null || String.valueOf(entry.get("subject")).isEmpty() ? "" : "<p><small>Subject: " + esc(entry.get("subject")) + "</small></p>";
            String table = rows.length() == 0 ? "" : "<table class=\"facts members\">" + rows + "</table>";
            String ended = Boolean.TRUE.equals(entry.get("ended")) ? " ended" : "";
            String family = String.valueOf(entry.get("family"));
            return "<li class=\"log-item\" data-id=\"" + entry.get("id") + "\"><div class=\"log-top\"><span class=\"badge " + family.toLowerCase(Locale.ROOT)
                + "\">" + esc(family) + "</span> <strong>" + esc(shortType(String.valueOf(entry.get("type")))) + "</strong> <time>" + esc(entry.get("at"))
                + "</time></div><p class=\"log-outcome" + ended + "\">" + esc(about) + "</p>" + subject + table + "<p><small>jti " + esc(entry.get("jti")) + "</small></p></li>";
        }

        String accountBar(List<Held> accounts, Session current) {
            StringBuilder items = new StringBuilder();
            for (Held item : accounts) {
                String name = esc(item.session.login.nameId);
                if (item.session == current) items.append("<li aria-current=\"true\"><strong>").append(name).append("</strong></li>");
                else items.append("<li><a href=\"/u/").append(esc(item.session.account)).append("/\">").append(name).append("</a></li>");
            }
            String allOut = accounts.size() > 1
                ? "<form method=\"post\" action=\"/logout\" class=\"inline\"><button type=\"submit\" class=\"secondary small\">Sign out of all accounts</button></form>"
                : "";
            return "<nav class=\"accounts\" aria-label=\"Accounts in this browser\"><span class=\"accounts-label\">Signed in here:</span> <ul>"
                + items + "</ul><a class=\"button small\" href=\"/login?add=1\">Add another account</a>" + allOut + "</nav>";
        }

        String tabs(String base, String active, int count) {
            String shown = count == 0 ? "" : String.valueOf(count);
            return "<nav class=\"page-tabs\" role=\"tablist\" aria-label=\"Sections\">" + tab(base, "identity", "Identity", active)
                + tab(base, "events", "CAEP &amp; RISC events <span class=\"count\" id=\"signal-count\">" + shown + "</span>", active) + "</nav>";
        }

        String tab(String base, String name, String label, String active) {
            String current = name.equals(active) ? " aria-current=\"page\"" : "";
            return "<a class=\"page-tab\" role=\"tab\" href=\"" + base + "/?tab=" + name + "\" aria-selected=\"" + name.equals(active) + "\"" + current + ">" + label + "</a>";
        }

        String page(String title, String body) {
            return "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>"
                + esc(title) + "</title><link rel=\"stylesheet\" href=\"/styles.css\"></head>\n<body><header><a href=\"/\">saml2-sp demo</a></header><main>\n"
                + body + "\n</main><footer>A traditional web application signing in with SAML 2.0.</footer></body>\n</html>\n";
        }

        void send(HttpExchange exchange, int status, byte[] body, Map<String, String> extra, List<String> cookies, boolean[] started) throws IOException {
            started[0] = true;
            Headers out = exchange.getResponseHeaders();
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("content-type", status == 204 ? null : "text/html; charset=utf-8");
            headers.put("cache-control", "no-store");
            headers.put("referrer-policy", "no-referrer");
            headers.put("x-content-type-options", "nosniff");
            headers.put("x-frame-options", "DENY");
            headers.put("content-security-policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
            if (extra != null) extra.forEach((key, value) -> headers.put(key.toLowerCase(Locale.ROOT), value));
            headers.forEach((key, value) -> { if (value != null) out.set(key, value); });
            if (cookies != null) for (String cookie : cookies) out.add("Set-Cookie", cookie);
            if (status == 204) {
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
                return;
            }
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        }

        void redirect(HttpExchange exchange, String location, int status, List<String> cookies, boolean[] started) throws IOException {
            started[0] = true;
            Headers out = exchange.getResponseHeaders();
            out.set("Cache-Control", "no-store");
            if (location != null) out.set("Location", location);
            if (cookies != null) for (String cookie : cookies) out.add("Set-Cookie", cookie);
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        }

        String cookie(String name, String value, String path, Integer maxAge, String sameSite) {
            StringBuilder parts = new StringBuilder();
            parts.append(name).append("=").append(percentEncode(value)).append("; Path=").append(path).append("; HttpOnly; SameSite=").append(sameSite);
            if (secureCookies) parts.append("; Secure");
            if (maxAge != null) parts.append("; Max-Age=").append(maxAge);
            return parts.toString();
        }

        String sealed(Object value) {
            String body = Base64.getUrlEncoder().withoutPadding().encodeToString(Json.stringify(value).getBytes(StandardCharsets.UTF_8));
            return body + "." + mac(body);
        }

        Object unseal(String token) {
            if (token == null || !token.contains(".")) return null;
            String body = token.substring(0, token.indexOf('.'));
            String tag = token.substring(token.indexOf('.') + 1);
            if (!MessageDigest.isEqual(mac(body).getBytes(StandardCharsets.UTF_8), tag.getBytes(StandardCharsets.UTF_8))) return null;
            try {
                return Json.parse(new String(Base64.getUrlDecoder().decode(body), StandardCharsets.UTF_8));
            } catch (Exception err) {
                Caught.warn(err);
                return null;
            }
        }

        String mac(String value) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(secret, "HmacSHA256"));
                return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
            } catch (Exception err) {
                Caught.error(err);
                throw new IllegalStateException(err);
            }
        }

        String readBody(HttpExchange exchange) throws IOException {
            String declared = exchange.getRequestHeaders().getFirst("Content-Length");
            if (declared != null && !declared.isBlank() && Long.parseLong(declared.trim()) > MAX_BODY) {
                throw new IllegalArgumentException("the request body is too large");
            }
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int read;
            try (InputStream in = exchange.getRequestBody()) {
                while ((read = in.read(chunk)) >= 0) {
                    if (buffer.size() + read > MAX_BODY) throw new IllegalArgumentException("the request body is too large");
                    buffer.write(chunk, 0, read);
                }
            }
            return buffer.toString(StandardCharsets.UTF_8);
        }

        Map<String, String> cookies(HttpExchange exchange) {
            return cookiesOf(cookieHeader(exchange));
        }

        String cookieHeader(HttpExchange exchange) {
            return exchange.getRequestHeaders().getFirst("Cookie");
        }
    }

    static String acsPath(ServiceProvider sp) {
        try {
            String path = URI.create(sp.config.acsUrl).getRawPath();
            return path == null || path.isEmpty() ? "/" : path;
        } catch (Exception err) {
            Caught.error(err);
            return "/";
        }
    }

    static boolean samePerson(SamlLogin left, SamlLogin right) {
        return String.valueOf(left.issuer).equals(String.valueOf(right.issuer))
            && String.valueOf(left.nameId).equals(String.valueOf(right.nameId))
            && String.valueOf(left.nameIdFormat == null ? "" : left.nameIdFormat).equals(right.nameIdFormat == null ? "" : right.nameIdFormat);
    }

    static String onPort(String url, int port) {
        URI uri = URI.create(url);
        String host = uri.getHost();
        if (host == null || !LOOPBACK.contains(host)) return url;
        String hostname = host.contains(":") ? "[" + host + "]" : host;
        String user = uri.getRawUserInfo();
        String netloc = (user == null || user.isEmpty() ? "" : user + "@") + hostname + ":" + port;
        return rebuild(uri.getScheme(), netloc, uri);
    }

    static String move(String value, URI base) {
        URI parsed = URI.create(value);
        String hostname = base.getHost() == null ? "" : base.getHost();
        if (hostname.contains(":")) hostname = "[" + hostname + "]";
        String netloc = hostname;
        if (base.getPort() >= 0) netloc = hostname + ":" + base.getPort();
        return rebuild(base.getScheme(), netloc, parsed);
    }

    static String rebuild(String scheme, String netloc, URI parsed) {
        StringBuilder out = new StringBuilder();
        out.append(scheme).append("://").append(netloc);
        if (parsed.getRawPath() != null) out.append(parsed.getRawPath());
        if (parsed.getRawQuery() != null) out.append("?").append(parsed.getRawQuery());
        if (parsed.getRawFragment() != null) out.append("#").append(parsed.getRawFragment());
        return out.toString();
    }

    static Map<String, List<String>> query(String raw) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) return out;
        for (String pair : raw.split("&", -1)) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String name = urlDecode(eq < 0 ? pair : pair.substring(0, eq));
            String value = eq < 0 ? "" : urlDecode(pair.substring(eq + 1));
            out.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
        }
        return out;
    }

    static String first(Map<String, List<String>> query, String name) {
        List<String> values = query.get(name);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    static int number(String value, int fallback) {
        if (value == null || value.isBlank()) return fallback;
        return Integer.parseInt(value.trim());
    }

    static String urlDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    static Map<String, String> cookiesOf(String header) {
        Map<String, String> out = new LinkedHashMap<>();
        if (header == null) return out;
        for (String part : header.split(";")) {
            if (!part.contains("=")) continue;
            int eq = part.indexOf('=');
            out.put(part.substring(0, eq).trim(), percentDecode(part.substring(eq + 1).trim()));
        }
        return out;
    }

    static String percentEncode(String value) {
        StringBuilder out = new StringBuilder();
        for (byte item : value.getBytes(StandardCharsets.UTF_8)) {
            int c = item & 0xff;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || "-_.!~*()".indexOf(c) >= 0) out.append((char) c);
            else out.append(String.format("%%%02X", c));
        }
        return out.toString();
    }

    static String percentDecode(String value) {
        byte[] buffer = new byte[value.length()];
        int size = 0;
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if (c == '%' && index + 2 < value.length()) {
                int hi = Character.digit(value.charAt(index + 1), 16);
                int lo = Character.digit(value.charAt(index + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    buffer[size++] = (byte) ((hi << 4) + lo);
                    index += 2;
                    continue;
                }
            }
            buffer[size++] = (byte) c;
        }
        return new String(buffer, 0, size, StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object value) {
        if (!(value instanceof Map<?, ?> map)) return null;
        Map<String, Object> out = new LinkedHashMap<>();
        map.forEach((key, item) -> out.put(String.valueOf(key), item));
        return out;
    }

    static String member(Object value) {
        if (value == null) return "";
        if (value instanceof Map<?, ?> map) {
            boolean allStrings = !map.isEmpty();
            for (Object item : map.values()) if (!(item instanceof String)) allStrings = false;
            if (allStrings) {
                StringBuilder joined = new StringBuilder();
                for (Object item : map.values()) {
                    if (joined.length() > 0) joined.append(" / ");
                    joined.append(item);
                }
                return joined.toString();
            }
            return Json.stringify(map);
        }
        return String.valueOf(value);
    }

    static String shortType(String uri) {
        int at = uri == null ? -1 : uri.lastIndexOf("/event-type/");
        return at < 0 ? String.valueOf(uri) : uri.substring(at + "/event-type/".length());
    }

    static String familyOf(String uri) {
        if (uri != null && uri.contains("/caep/")) return "CAEP";
        if (uri != null && uri.contains("/risc/")) return "RISC";
        return "SSF";
    }

    static String messageOf(Throwable err) {
        String message = err.getMessage();
        return message == null || message.isBlank() ? err.toString() : message;
    }

    static String esc(Object value) {
        String text = value == null ? "" : String.valueOf(value);
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    static String b64(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    static byte[] random(int size) {
        byte[] data = new byte[size];
        RANDOM.nextBytes(data);
        return data;
    }
}
