// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml.ssf;

import com.iyasec.saml.Backchannel;
import com.iyasec.saml.Caught;
import com.iyasec.saml.Json;
import com.iyasec.saml.SamlError;
import com.iyasec.saml.SamlLogin;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/** A Shared Signals receiver: one poll stream of CAEP and RISC events (RFC 8936). */
public final class SignalsReceiver {
    public static final String POLL_METHOD = "urn:ietf:rfc:8936";

    @FunctionalInterface
    public interface EndSessions {
        void end(List<String> sessions, SignalEvent event);
    }

    @FunctionalInterface
    public interface Handler {
        void on(SignalEvent event);
    }

    public interface Log {
        void info(String message);
        void warn(String message);
        void error(String message);
    }

    private final String transmitter;
    private final EndSessions onEnd;
    private Map<String, String> tls = Map.of();
    private Supplier<Map<String, String>> headers = Map::of;
    private List<String> eventsRequested = new ArrayList<>(Events.DEFAULT_EVENTS_REQUESTED);
    private List<String> endOn = new ArrayList<>(Events.DEFAULT_ENDING_EVENTS);
    private MemorySessionIndex index = new MemorySessionIndex();
    private String subjectAttribute;
    private String description;
    private int pollIntervalMs = 5000;
    private int maxEvents = 50;
    private Log log = new Log() {
        public void info(String message) { System.out.println(message); }
        public void warn(String message) { System.out.println(message); }
        public void error(String message) { System.out.println(message); }
    };
    private Map<String, Object> config;
    private Map<String, Object> stream;
    private List<Map<String, Object>> keys = List.of();
    private long keysAt;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "saml2-sp-ssf");
        thread.setDaemon(true);
        return thread;
    });
    private ScheduledFuture<?> timer;
    private volatile boolean running;
    private final List<String> ack = new ArrayList<>();
    private final Map<String, Object> errs = new LinkedHashMap<>();
    private final Map<String, List<Handler>> handlers = new LinkedHashMap<>();
    private CompletableFuture<Boolean> inflight;
    private final Object gate = new Object();

    public SignalsReceiver(String transmitter, EndSessions onEndSessions) {
        if (onEndSessions == null) throw new SamlError("config", "onEndSessions is required");
        if (transmitter == null || !transmitter.matches("(?i)https?://.*")) {
            throw new SamlError("config", "transmitter must be an http(s) URL");
        }
        this.transmitter = transmitter.replaceAll("/+$", "");
        this.onEnd = onEndSessions;
    }

    public SignalsReceiver tls(Map<String, String> tls) { this.tls = tls == null ? Map.of() : tls; return this; }
    public SignalsReceiver headers(Supplier<Map<String, String>> headers) { this.headers = headers == null ? Map::of : headers; return this; }
    public SignalsReceiver eventsRequested(List<String> events) { this.eventsRequested = new ArrayList<>(events); return this; }
    public SignalsReceiver endOn(List<String> events) { this.endOn = new ArrayList<>(events); return this; }
    public SignalsReceiver sessionIndex(MemorySessionIndex index) { this.index = index; return this; }
    public SignalsReceiver subjectAttribute(String attribute) { this.subjectAttribute = attribute; return this; }
    public SignalsReceiver description(String description) { this.description = description; return this; }
    public SignalsReceiver pollIntervalMs(int pollIntervalMs) { this.pollIntervalMs = pollIntervalMs; return this; }
    public SignalsReceiver maxEvents(int maxEvents) { this.maxEvents = maxEvents; return this; }
    public SignalsReceiver log(Log log) { this.log = log; return this; }

    public Map<String, Object> stream() { return stream; }

    public void track(String localId, SamlLogin login) { track(localId, login, null); }

    public void track(String localId, SamlLogin login, Instant expiresAt) {
        index.add(MemorySessionIndex.trackedFrom(localId, login, subjectAttribute, expiresAt));
    }

    public void untrack(String localId) { index.remove(localId); }

    public SignalsReceiver on(String eventType, Handler handler) {
        handlers.computeIfAbsent(eventType, key -> new ArrayList<>()).add(handler);
        return this;
    }

    public void start() {
        if (running) return;
        config = discover();
        jwks(true);
        stream = ensureStream();
        Object delivery = stream.get("delivery");
        if (!(delivery instanceof Map<?, ?> map) || !(map.get("endpoint_url") instanceof String)) {
            throw new SamlError("ssf", "the stream has no poll endpoint_url");
        }
        running = true;
        Object delivered = stream.get("events_delivered");
        int count = delivered instanceof List<?> list ? list.size() : 0;
        log.info("ssf: polling stream " + stream.get("stream_id") + " at " + map.get("endpoint_url") + ", delivering " + count + " event type(s)");
        iteration();
    }

    public void stop() {
        running = false;
        if (timer != null) timer.cancel(false);
        timer = null;
    }

    public boolean pollOnce() {
        CompletableFuture<Boolean> mine = null;
        CompletableFuture<Boolean> waitFor;
        synchronized (gate) {
            if (inflight != null) waitFor = inflight;
            else {
                inflight = new CompletableFuture<>();
                mine = inflight;
                waitFor = null;
            }
        }
        if (waitFor != null) {
            try {
                return waitFor.join();
            } catch (CompletionException err) {
                Caught.error(err);
                Throwable cause = err.getCause() == null ? err : err.getCause();
                if (cause instanceof RuntimeException runtime) throw runtime;
                throw new SamlError("ssf", String.valueOf(cause), cause);
            }
        }
        try {
            boolean result = pollNow();
            mine.complete(result);
            return result;
        } catch (RuntimeException err) {
            Caught.error(err);
            mine.completeExceptionally(err);
            throw err;
        } finally {
            synchronized (gate) { inflight = null; }
        }
    }

    public void verify(String state) {
        Object endpoint = config == null ? null : config.get("verification_endpoint");
        if (!(endpoint instanceof String url)) throw new SamlError("ssf", "the transmitter publishes no verification_endpoint");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("stream_id", stream.get("stream_id"));
        if (state != null && !state.isEmpty()) body.put("state", state);
        Reply reply = call("POST", url, body);
        if (reply.status != 200 && reply.status != 204) throw new SamlError("ssf", "verification answered " + reply.status);
    }

    private void iteration() {
        if (!running) return;
        long delay = pollIntervalMs;
        try {
            if (pollOnce()) delay = 0;
        } catch (Exception err) {
            Caught.warn(err);
            log.warn("ssf: poll failed: " + err);
            delay = Math.min(pollIntervalMs * 4L, 60_000L);
        }
        if (running) timer = scheduler.schedule(this::iteration, delay, TimeUnit.MILLISECONDS);
    }

    private boolean pollNow() {
        Object delivery = stream.get("delivery");
        String url = String.valueOf(((Map<?, ?>) delivery).get("endpoint_url"));
        List<String> pendingAck = new ArrayList<>(ack);
        Map<String, Object> pendingErrs = new LinkedHashMap<>(errs);
        ack.clear();
        errs.clear();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("maxEvents", maxEvents);
        body.put("returnImmediately", true);
        if (!pendingAck.isEmpty()) body.put("ack", pendingAck);
        if (!pendingErrs.isEmpty()) body.put("setErrs", pendingErrs);
        Reply reply;
        try {
            reply = call("POST", url, body);
        } catch (RuntimeException err) {
            Caught.error(err);
            ack.addAll(0, pendingAck);
            errs.putAll(pendingErrs);
            throw err;
        }
        if (reply.status != 200) {
            ack.addAll(0, pendingAck);
            errs.putAll(pendingErrs);
            throw new SamlError("ssf", "the poll answered " + reply.status + ": " + clip(reply.json));
        }
        Map<String, Object> payload = reply.json instanceof Map<?, ?> map ? cast(map) : Map.of();
        Object sets = payload.get("sets");
        if (sets instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String jti = String.valueOf(entry.getKey());
                try {
                    handle(jti, String.valueOf(entry.getValue()));
                    ack.add(jti);
                } catch (Exception err) {
                    Caught.warn(err);
                    log.warn("ssf: SET " + jti + " refused: " + err);
                    String kind = err instanceof SamlError saml && "signature".equals(saml.code) ? "invalid_key" : "invalid_request";
                    Map<String, String> problem = new LinkedHashMap<>();
                    problem.put("err", kind);
                    problem.put("description", String.valueOf(err.getMessage() == null ? err : err.getMessage()));
                    errs.put(jti, problem);
                }
            }
        }
        return Boolean.TRUE.equals(payload.get("moreAvailable"));
    }

    private void handle(String jti, String token) {
        Jws.Verified verified;
        try {
            verified = Jws.verifyCompact(token, keys);
        } catch (SamlError err) {
            if (err.getMessage() == null || !err.getMessage().matches("(?s).*(publishes no|does not verify).*")) throw err;
            verified = Jws.verifyCompact(token, jwks(true));
        }
        Map<String, Object> header = verified.header();
        Map<String, Object> payload = verified.payload();
        if (header.get("typ") != null && !"secevent+jwt".equalsIgnoreCase(String.valueOf(header.get("typ")))) {
            throw new SamlError("validation", "the SET's typ is " + header.get("typ"));
        }
        if (!String.valueOf(config.get("issuer")).equals(String.valueOf(payload.get("iss")))) {
            throw new SamlError("validation", "the SET was issued by " + payload.get("iss") + ", not " + config.get("issuer"));
        }
        List<String> wanted = strings(stream.get("aud"));
        List<String> audience = strings(payload.get("aud"));
        if (!wanted.isEmpty() && audience.stream().noneMatch(wanted::contains)) {
            throw new SamlError("validation", "the SET is for " + String.join(", ", audience) + ", not this stream");
        }
        if (payload.get("jti") != null && !payload.get("jti").equals(jti)) {
            throw new SamlError("validation", "the SET's jti is not the one it was delivered under");
        }
        Object events = payload.get("events");
        if (!(events instanceof Map<?, ?> eventMap) || eventMap.isEmpty()) throw new SamlError("validation", "the SET carries no events");
        for (Map.Entry<?, ?> entry : eventMap.entrySet()) {
            String eventType = String.valueOf(entry.getKey());
            Object body = entry.getValue();
            Object subId = payload.get("sub_id") != null ? payload.get("sub_id") : (body instanceof Map<?, ?> map ? map.get("subject") : null);
            Map<String, String> subject = Events.subjectOf(subId, String.valueOf(config.get("issuer")));
            List<String> sessions = sessionsFor(eventType, subject);
            boolean ends = endOn.contains(eventType) && !sessions.isEmpty();
            SignalEvent event = new SignalEvent();
            event.type = eventType;
            event.payload = body instanceof Map<?, ?> map ? cast(map) : Map.of();
            event.subject = subject;
            event.jti = jti;
            event.sessions = sessions;
            event.ended = ends;
            event.iat = payload.get("iat") instanceof Number number && !(payload.get("iat") instanceof Boolean) ? number.doubleValue() : null;
            event.txn = payload.get("txn") instanceof String text ? text : null;
            if (ends) {
                try {
                    onEnd.end(sessions, event);
                } catch (Exception err) {
                    Caught.error(err);
                    log.error("ssf: onEndSessions threw for " + eventType + " (SET " + jti + " is still acknowledged): " + err);
                    event.ended = false;
                }
                if (event.ended) for (String localId : sessions) index.remove(localId);
            }
            List<Handler> both = new ArrayList<>();
            if (handlers.get(eventType) != null) both.addAll(handlers.get(eventType));
            if (handlers.get("*") != null) both.addAll(handlers.get("*"));
            for (Handler handler : both) {
                try {
                    handler.on(event);
                } catch (Exception err) {
                    Caught.error(err);
                    log.error("ssf: a handler for " + eventType + " threw (SET " + jti + " is still acknowledged): " + err);
                }
            }
        }
    }

    private List<String> sessionsFor(String eventType, Map<String, String> subject) {
        if (eventType.equals(Events.EVENT.get("verification")) || eventType.equals(Events.EVENT.get("stream_updated"))) return List.of();
        if (subject.get("idpSession") != null) {
            List<String> found = index.byIdpSession(subject.get("idpSession"));
            if (!found.isEmpty() || eventType.equals(Events.EVENT.get("session_revoked"))) return found;
        }
        if (subject.get("person") != null) return index.byPerson(subject.get("person"));
        if (subject.get("email") != null) return index.byEmail(subject.get("email"));
        return List.of();
    }

    private Map<String, Object> discover() {
        String url = transmitter + "/.well-known/ssf-configuration";
        Reply reply = call("GET", url, null);
        if (reply.status != 200 || !(reply.json instanceof Map<?, ?> map) || map.get("configuration_endpoint") == null || map.get("jwks_uri") == null) {
            throw new SamlError("ssf", url + " answered " + reply.status + " without a usable transmitter configuration");
        }
        Object supported = map.get("delivery_methods_supported");
        if (supported instanceof List<?> list && list.stream().noneMatch(POLL_METHOD::equals)) {
            throw new SamlError("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
        }
        return cast(map);
    }

    private List<Map<String, Object>> jwks(boolean force) {
        if (!force && !keys.isEmpty() && (System.currentTimeMillis() - keysAt) < 3_600_000L) return keys;
        Reply reply = call("GET", String.valueOf(config.get("jwks_uri")), null);
        Object raw = reply.json instanceof Map<?, ?> map ? map.get("keys") : null;
        if (reply.status != 200 || !(raw instanceof List<?> list)) throw new SamlError("ssf", "the transmitter's JWKS answered " + reply.status);
        List<Map<String, Object>> parsed = new ArrayList<>();
        for (Object item : list) if (item instanceof Map<?, ?> map) parsed.add(cast(map));
        keys = parsed;
        keysAt = System.currentTimeMillis();
        return keys;
    }

    private Map<String, Object> ensureStream() {
        String endpoint = String.valueOf(config.get("configuration_endpoint"));
        Reply listed = call("GET", endpoint, null);
        if (listed.status == 200) {
            List<Object> all = listed.json instanceof List<?> list ? new ArrayList<>(list) : (listed.json == null ? List.of() : List.of(listed.json));
            for (Object item : all) {
                if (item instanceof Map<?, ?> map) {
                    Object delivery = map.get("delivery");
                    if (delivery instanceof Map<?, ?> method && POLL_METHOD.equals(method.get("method")) && map.get("stream_id") != null) {
                        return cast(map);
                    }
                }
            }
        } else if (listed.status != 404) {
            throw new SamlError("ssf", "listing the streams at " + endpoint + " answered " + listed.status + ": " + clip(listed.json));
        }
        Map<String, Object> createdBody = new LinkedHashMap<>();
        createdBody.put("delivery", Map.of("method", POLL_METHOD));
        createdBody.put("events_requested", eventsRequested);
        if (description != null && !description.isEmpty()) createdBody.put("description", description);
        Reply created = call("POST", endpoint, createdBody);
        Map<String, Object> stream = created.json instanceof Map<?, ?> map ? cast(map) : Map.of();
        if ((created.status != 200 && created.status != 201) || stream.get("stream_id") == null) {
            throw new SamlError("ssf", "creating a stream at " + endpoint + " answered " + created.status + ": " + clip(created.json));
        }
        return stream;
    }

    private Reply call(String method, String url, Object body) {
        Map<String, String> requestHeaders = new LinkedHashMap<>();
        requestHeaders.put("accept", "application/json");
        Map<String, String> extra = headers.get();
        if (extra != null) requestHeaders.putAll(extra);
        String payload = null;
        if (body != null) {
            requestHeaders.put("content-type", "application/json");
            payload = Json.stringify(body);
        }
        Backchannel.Answer answer = Backchannel.send(url, method, requestHeaders, payload, tls, "ssf");
        Object parsed = null;
        if (answer.body() != null && !answer.body().isEmpty()) {
            try {
                parsed = Json.parse(answer.body());
            } catch (Exception err) {
                Caught.error(err);
                parsed = answer.body();
            }
        }
        return new Reply(answer.status(), parsed);
    }

    private static List<String> strings(Object value) {
        if (value instanceof List<?> list) {
            List<String> out = new ArrayList<>();
            for (Object item : list) out.add(String.valueOf(item));
            return out;
        }
        if (value == null) return List.of();
        return List.of(String.valueOf(value));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cast(Map<?, ?> map) {
        return (Map<String, Object>) map;
    }

    private static String clip(Object value) {
        String text = value instanceof String textValue ? textValue : Json.stringify(value);
        if (text == null) return "";
        return text.length() > 300 ? text.substring(0, 300) : text;
    }

    private record Reply(int status, Object json) {}
}
