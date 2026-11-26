// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml.pep;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Access;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Obligation;
import com.iyasec.pep.Pep;
import com.iyasec.saml.SamlLogin;
import com.iyasec.saml.ServiceProvider;
import com.iyasec.saml.StubIdp;
import com.iyasec.saml.ssf.MemorySessionIndex;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/** The AuthZEN case table, decided by a local service provider. */
class AuthzenTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SESSION = "L-authzen";
    private static final Pattern SUBJECT = Pattern.compile("subject-id\"[^>]*>\\s*<AttributeValue[^>]*>([^<]*)<");
    private static final Pattern DESIGNATOR = Pattern.compile("<AttributeDesignator[^>]*Category=\"([^\"]*)\"[^>]*AttributeId=\"([^\"]*)\"[^>]*DataType=\"([^\"]*)\"");

    private static final byte[] TOKEN = "{\"access_token\":\"azn-token\",\"token_type\":\"DPoP\",\"expires_in\":300}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] REGISTERED = "{\"registered\":true,\"identity\":\"uid=pep-azn,ou=users,dc=azn\"}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HEARTBEAT = "{\"acknowledged\":true,\"current\":true}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AUDIT = "{\"acknowledged\":0}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] UNAUTHORIZED = "{\"error\":\"invalid_token\"}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] NOT_FOUND = "{\"error\":\"not_found\"}".getBytes(StandardCharsets.UTF_8);

    @Test
    void theTableDecidesAsItSaysOffline() throws Exception {
        JsonNode table = JSON.readTree(textResource("cases.json"));
        assertTrue(table.path("cases").isArray(), "authzen/cases.json has no cases");
        List<String> failures = new ArrayList<>();
        int run = 0;
        for (String phase : List.of("root", "application")) {
            byte[] catalogue = catalogueOf(table, phase);
            byte[] policies = policiesOf(table, phase);
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
                Thread thread = new Thread(runnable, "saml-authzen");
                thread.setDaemon(true);
                return thread;
            });
            server.createContext("/", exchange -> answer(exchange, table, catalogue, policies));
            server.setExecutor(executor);
            server.start();
            Path key = null;
            ServiceProvider provider = null;
            try {
                key = ecKey("azn-" + phase);
                provider = provider(server.getAddress().getPort(), key, table);
                waitHeld(provider.pep());
                assertEquals(subjectRoots(table), provider.pep().status().catalogueSubjectProperties, "every subject row of the table was read: " + provider.pep().status().lastError);
                for (JsonNode one : table.get("cases")) {
                    if (!phase.equals(phaseOf(one))) continue;
                    run++;
                    Decision decision = ask(provider, table, one);
                    boolean matches = expected(decision, one.get("expect"));
                    JsonNode defect = one.get("knownLocalDefect");
                    if (defect != null && defect.isTextual()) {
                        if (matches) {
                            failures.add(one.path("name").asText() + ": local now answers as expected; remove knownLocalDefect");
                        }
                    } else if (!matches) {
                        failures.add(one.path("name").asText() + " [" + phase + "]: " + described(decision) + ", the table says " + one.get("expect"));
                    }
                }
            } finally {
                if (provider != null && provider.pep() != null) {
                    try {
                        provider.pep().stop();
                    } catch (RuntimeException ignored) {
                        // Still close the stub.
                    }
                }
                server.stop(0);
                executor.shutdownNow();
                if (key != null) {
                    try {
                        Files.deleteIfExists(key);
                    } catch (IOException ignored) {
                        // The key file is in the temporary directory.
                    }
                }
            }
        }
        assertEquals(table.get("cases").size(), run, "every case has a phase this runner knows");
        assertTrue(failures.isEmpty(), failures.size() + " of " + run + " cases:\n" + String.join("\n", failures));
    }

    private static ServiceProvider provider(int port, Path key, JsonNode table) {
        List<String> obligations = new ArrayList<>();
        for (JsonNode item : table.path("supportedObligations")) {
            if (item.isTextual()) obligations.add(item.asText());
        }
        Map<String, Object> section = new LinkedHashMap<>();
        section.put("name", "pep-azn");
        section.put("mode", "local");
        section.put("assertionKey", key.toString());
        section.put("pdpUrl", "http://127.0.0.1:" + port + "/realm/azn");
        section.put("heartbeatIntervalMs", 60000);
        section.put("pollIntervalMs", 60000);
        section.put("decisionRecords", false);
        section.put("supportedObligations", obligations);
        Map<String, Object> config = base();
        config.put("pep", section);
        return ServiceProvider.create(config);
    }

    private static void waitHeld(Pep pep) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (System.nanoTime() < deadline) {
            if (pep.status().holdsPolicy) return;
            Thread.sleep(100);
        }
        assertTrue(pep.status().holdsPolicy, "the local PEP did not hold the table's policy: " + pep.status().lastError);
    }

    private static int subjectRoots(JsonNode table) {
        Set<String> roots = new HashSet<>();
        for (JsonNode row : table.path("catalogue")) {
            if (!"subject".equals(row.path("object").asText())) continue;
            String property = row.path("property").asText();
            int dot = property.indexOf('.');
            roots.add(dot < 0 ? property : property.substring(0, dot));
        }
        return roots.size();
    }

    private static String phaseOf(JsonNode one) {
        JsonNode phase = one.get("phase");
        if (phase != null && phase.isTextual()) return phase.asText();
        return "root";
    }

    private static Decision ask(ServiceProvider provider, JsonNode table, JsonNode one) {
        String name = one.path("login").asText();
        JsonNode base = table.path("logins").path(name);
        assertTrue(base.isObject(), "no login " + name);
        SamlLogin login = loginOf(base, one);
        Access access = accessOf(one.path("access"));
        JsonNode session = one.get("session");
        if (session == null || !session.isTextual()) return provider.decide(login, access);
        MemorySessionIndex index = new MemorySessionIndex();
        if ("tracked".equals(session.asText())) {
            index.add(new MemorySessionIndex.Tracked(SESSION, "azn", null, "IDP-AZN", null));
        }
        return provider.decideSession(index, SESSION, login, access);
    }

    private static SamlLogin loginOf(JsonNode base, JsonNode one) {
        Map<String, List<String>> attributes = new LinkedHashMap<>();
        mergeAttributes(attributes, base.get("attributes"));
        mergeAttributes(attributes, one.get("attributes"));
        Map<String, String> friendly = new LinkedHashMap<>();
        mergeFriendly(friendly, base.get("friendlyNames"));
        mergeFriendly(friendly, one.get("friendlyNames"));
        String acr = "";
        JsonNode acrNode = one.has("acr") ? one.get("acr") : base.get("acr");
        if (acrNode != null && acrNode.isTextual()) acr = acrNode.asText();
        SamlLogin login = new SamlLogin();
        login.nameId = base.path("nameId").asText("");
        login.nameIdFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
        login.sessionIndex = "IDP-AZN";
        login.authnInstant = Instant.ofEpochMilli(1_760_000_000_000L);
        login.authnContextClassRef = acr;
        login.attributes = attributes;
        login.attributeFriendlyNames = friendly;
        login.issuer = StubIdp.IDP_ENTITY;
        return login;
    }

    private static void mergeAttributes(Map<String, List<String>> attributes, JsonNode source) {
        if (source == null || !source.isObject()) return;
        source.fields().forEachRemaining(field -> {
            if (field.getValue().isNull()) attributes.remove(field.getKey());
            else attributes.put(field.getKey(), strings(field.getValue()));
        });
    }

    private static void mergeFriendly(Map<String, String> friendly, JsonNode source) {
        if (source == null || !source.isObject()) return;
        source.fields().forEachRemaining(field -> friendly.put(field.getKey(), field.getValue().asText("")));
    }

    private static List<String> strings(JsonNode value) {
        List<String> out = new ArrayList<>();
        if (value != null && value.isArray()) {
            for (JsonNode item : value) {
                if (item.isTextual()) out.add(item.asText());
            }
        }
        return out;
    }

    private static Access accessOf(JsonNode access) {
        Access out = Access.of(access.path("action").asText(""), access.path("type").asText(""), access.path("id").asText(""));
        out.resourceProperties = properties(access.get("resource"));
        out.actionProperties = properties(access.get("actionProperties"));
        out.context = properties(access.get("context"));
        return out;
    }

    private static Map<String, JsonNode> properties(JsonNode node) {
        Map<String, JsonNode> out = new LinkedHashMap<>();
        if (node != null && node.isObject()) {
            node.fields().forEachRemaining(field -> out.put(field.getKey(), field.getValue().deepCopy()));
        }
        return out;
    }

    private static boolean expected(Decision decision, JsonNode expect) {
        if (expect == null || !expect.isObject()) return false;
        String want = expect.path("decision").asText();
        String got = decision.kind() == Decision.Kind.PERMIT ? "Permit" : decision.kind() == Decision.Kind.DENY ? "Deny" : "Unavailable";
        if (!got.equals(want)) return false;
        if (!"Permit".equals(want)) return true;
        JsonNode wantObligations = expect.get("obligations");
        int count = wantObligations != null && wantObligations.isArray() ? wantObligations.size() : 0;
        List<Obligation> obligations = decision.obligations();
        if (obligations.size() != count) return false;
        for (int i = 0; i < count; i++) {
            JsonNode wanted = wantObligations.get(i);
            Obligation obligation = obligations.get(i);
            if (!obligation.kind.equals(wanted.path("type").asText())) return false;
            JsonNode properties = wanted.get("properties");
            if (properties == null || properties.isNull()) {
                if (!obligation.properties.isEmpty()) return false;
            } else if (!obligation.properties.equals(properties)) return false;
        }
        return true;
    }

    private static String described(Decision decision) {
        if (decision.kind() == Decision.Kind.PERMIT) {
            StringBuilder out = new StringBuilder("Permit");
            if (!decision.obligations().isEmpty()) {
                out.append(" [");
                boolean first = true;
                for (Obligation obligation : decision.obligations()) {
                    if (!first) out.append(", ");
                    first = false;
                    out.append(obligation.kind).append(' ').append(obligation.properties);
                }
                out.append(']');
            }
            return out.toString();
        }
        String name = decision.kind() == Decision.Kind.DENY ? "Deny" : "Unavailable";
        if (decision.why() == null || decision.why().isEmpty()) return name;
        return name + " (" + decision.why() + ")";
    }

    private static byte[] catalogueOf(JsonNode table, String phase) throws Exception {
        ObjectNode body = JSON.createObjectNode();
        body.put("syncToken", "azn-c");
        body.put("realm", "azn");
        body.set("rows", table.get("catalogue"));
        ArrayNode applications = body.putArray("fgaApplications");
        if ("application".equals(phase)) applications.add(StubIdp.SP_ENTITY);
        body.putObject("settings").put("obligationsProfile", true);
        return JSON.writeValueAsBytes(body);
    }

    private static byte[] policiesOf(JsonNode table, String phase) throws Exception {
        ObjectNode body = JSON.createObjectNode();
        body.put("syncToken", "azn-" + phase);
        body.put("scope", "bound-application");
        body.put("source", "root".equals(phase) ? "root" : "application");
        ArrayNode policies = body.putArray("policies");
        if ("root".equals(phase)) policies.add(policyRow(table, "root", true));
        else {
            policies.add(policyRow(table, "application", true));
            policies.add(policyRow(table, "shared", false));
        }
        body.putArray("withheld");
        body.put("note", "");
        return JSON.writeValueAsBytes(body);
    }

    private static ObjectNode policyRow(JsonNode table, String key, boolean root) {
        JsonNode policy = table.path("policies").path(key);
        String id = policy.path("policyId").asText();
        String file = policy.path("xacml").asText();
        String document = textResource(file);
        assertTrue(document.contains(id), file + " does not contain " + id);
        ObjectNode row = JSON.createObjectNode();
        JsonNode name = policy.get("name");
        row.put("name", name != null && name.isTextual() ? name.asText() : key);
        row.put("policyId", id);
        row.put("kind", policy.path("kind").asText());
        row.put("version", "1.0");
        row.put("isRoot", root);
        row.put("description", "");
        row.put("document", document);
        return row;
    }

    private static String pipAnswer(JsonNode table, String query) {
        Matcher subject = SUBJECT.matcher(query);
        String id = subject.find() ? subject.group(1) : "";
        JsonNode person = table.path("directory").path(id);
        StringBuilder out = new StringBuilder("<PIPResponse xmlns=\"urn:sts:xacml:pip:1.0\">");
        Matcher designators = DESIGNATOR.matcher(query);
        while (designators.find()) {
            JsonNode value = person.get(designators.group(2));
            if (value == null || !value.isTextual()) continue;
            out.append("<Attributes xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" Category=\"")
                .append(xml(designators.group(1)))
                .append("\"><Attribute AttributeId=\"")
                .append(xml(designators.group(2)))
                .append("\" IncludeInResult=\"false\"><AttributeValue DataType=\"")
                .append(xml(designators.group(3)))
                .append("\">")
                .append(xml(value.asText()))
                .append("</AttributeValue></Attribute></Attributes>");
        }
        out.append("</PIPResponse>");
        return out.toString();
    }

    private static String xml(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static void answer(HttpExchange exchange, JsonNode table, byte[] catalogue, byte[] policies) {
        try {
            byte[] raw = exchange.getRequestBody().readAllBytes();
            String path = route(exchange.getRequestURI().getPath());
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            if (!"/oauth2/token".equals(path) && (authorization == null || !authorization.startsWith("DPoP "))) {
                send(exchange, 401, "application/json", UNAUTHORIZED);
                return;
            }
            if ("/oauth2/token".equals(path)) send(exchange, 200, "application/json", TOKEN);
            else if ("/xacml/pep/register".equals(path)) send(exchange, 201, "application/json", REGISTERED);
            else if ("/xacml/pep/heartbeat".equals(path)) send(exchange, 200, "application/json", HEARTBEAT);
            else if ("/xacml/pep/authzen-catalogue".equals(path)) send(exchange, 200, "application/json", catalogue);
            else if ("/xacml/pep/policies".equals(path)) send(exchange, 200, "application/json", policies);
            else if ("/xacml/pip".equals(path)) send(exchange, 200, "application/xml", pipAnswer(table, new String(raw, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
            else if ("/admin-api/pep-audit".equals(path)) send(exchange, 200, "application/json", AUDIT);
            else send(exchange, 404, "application/json", NOT_FOUND);
        } catch (Exception err) {
            try {
                byte[] body = String.valueOf(err).getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(500, body.length);
                exchange.getResponseBody().write(body);
            } catch (Exception ignored) {
                // The exchange is already gone.
            }
        } finally {
            exchange.close();
        }
    }

    private static String route(String path) {
        String prefix = "/realm/azn";
        if (path != null && path.startsWith(prefix)) path = path.substring(prefix.length());
        if (path == null || path.isEmpty()) return "/";
        return path;
    }

    private static void send(HttpExchange exchange, int status, String type, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", type);
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static String textResource(String name) {
        String path = "/authzen/" + name;
        try (InputStream in = AuthzenTest.class.getResourceAsStream(path)) {
            if (in == null) throw new AssertionError("missing test resource " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException err) {
            throw new AssertionError(path, err);
        }
    }

    private static Path ecKey(String tag) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        byte[] encoded = generator.generateKeyPair().getPrivate().getEncoded();
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(encoded);
        String pem = "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
        Path path = Path.of(System.getProperty("java.io.tmpdir"), "saml2-sp-pep-" + tag + "-" + ProcessHandle.current().pid() + "-" + System.nanoTime() + ".pem");
        Files.writeString(path, pem);
        return path.toAbsolutePath();
    }

    private static Map<String, Object> base() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("entityId", StubIdp.SP_ENTITY);
        out.put("acsUrl", StubIdp.ACS);
        out.put("privateKey", StubIdp.SP_KEY);
        out.put("certificate", StubIdp.SP_CERT);
        out.put("idpMetadata", StubIdp.idpMetadata(null));
        return out;
    }
}
