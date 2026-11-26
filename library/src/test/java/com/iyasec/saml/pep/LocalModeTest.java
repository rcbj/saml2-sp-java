// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml.pep;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Access;
import com.iyasec.pep.Decision;
import com.iyasec.saml.SamlLogin;
import com.iyasec.saml.ServiceProvider;
import com.iyasec.saml.StubIdp;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** A local PEP fails closed until it holds a policy, then decides in process. */
class LocalModeTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String READ_ONLY = "<Policy xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" PolicyId=\"orders\" Version=\"1.0\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit\"><Target/><Rule RuleId=\"read\" Effect=\"Permit\"><Target><AnyOf><AllOf><Match MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\"><AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">read</AttributeValue><AttributeDesignator Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:action\" AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"false\"/></Match></AllOf></AnyOf></Target></Rule></Policy>";

    private static final byte[] TOKEN = json("{\"access_token\":\"pep-token\",\"token_type\":\"DPoP\",\"expires_in\":300}");
    private static final byte[] REGISTERED = json("{\"registered\":true}");
    private static final byte[] HEARTBEAT = json("{\"acknowledged\":true,\"current\":true}");
    private static final byte[] CATALOGUE = json("{\"syncToken\":\"c1\",\"rows\":[{\"object\":\"subject\",\"property\":\"acr\",\"attributeId\":\"urn:example:acr\"}],\"settings\":{\"obligationsProfile\":false}}");
    private static final byte[] AUDIT = json("{\"acknowledged\":0}");
    private static final byte[] PERMIT = json("{\"decision\":true}");
    private static final byte[] UNAUTHORIZED = json("{\"error\":\"invalid_token\"}");
    private static final byte[] NOT_NOW = json("{\"error\":\"server_error\",\"error_description\":\"not now\"}");
    private static final byte[] NOT_FOUND = json("{\"error\":\"not_found\"}");

    @Test
    void localModeFailsClosedThenDecidesInProcess() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "saml-pdp");
            thread.setDaemon(true);
            return thread;
        });
        AtomicBoolean policiesUp = new AtomicBoolean(false);
        AtomicInteger policies = new AtomicInteger();
        AtomicInteger evaluation = new AtomicInteger();
        byte[] held = readOnlyPolicy();
        server.createContext("/", exchange -> answer(exchange, policiesUp, policies, evaluation, held));
        server.setExecutor(executor);
        server.start();
        Path key = null;
        ServiceProvider provider = null;
        try {
            key = ecKey("local");
            Map<String, Object> config = base();
            Map<String, Object> section = new LinkedHashMap<>();
            section.put("name", "pep-local");
            section.put("mode", "local");
            section.put("pollIntervalMs", 1000);
            section.put("heartbeatIntervalMs", 60000);
            section.put("assertionKey", key.toString());
            section.put("pdpUrl", "http://127.0.0.1:" + server.getAddress().getPort());
            config.put("pep", section);
            provider = ServiceProvider.create(config);
            assertNotNull(provider.pep());
            assertFalse(provider.pep().config().signals, "no receiver: the PEP polls at pollIntervalMs");
            Decision closed = provider.decide(login(), Access.of("read", "order", "42"));
            assertEquals(Decision.Kind.UNAVAILABLE, closed.kind());

            policiesUp.set(true);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
            while (System.nanoTime() < deadline && !provider.pep().status().holdsPolicy) {
                Thread.sleep(100);
            }
            assertTrue(provider.pep().status().holdsPolicy, "the poll pulled once the service answered: " + provider.pep().status().lastError);
            assertTrue(provider.decide(login(), Access.of("read", "order", "42")).isPermit());
            assertEquals(Decision.Kind.DENY, provider.decide(login(), Access.of("write", "order", "42")).kind());
            assertEquals(0, evaluation.get(), "decided in process");
            assertTrue(policies.get() >= 2, "policies were requested " + policies.get() + " times");
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
                } catch (java.io.IOException ignored) {
                    // The key file is in the temporary directory.
                }
            }
        }
    }

    private static void answer(HttpExchange exchange, AtomicBoolean policiesUp, AtomicInteger policies, AtomicInteger evaluation, byte[] held) {
        try {
            exchange.getRequestBody().readAllBytes();
            String path = exchange.getRequestURI().getPath();
            if (path == null) path = "";
            if ("/xacml/pep/policies".equals(path)) policies.incrementAndGet();
            if ("/access/v1/evaluation".equals(path)) evaluation.incrementAndGet();
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            if (!"/oauth2/token".equals(path) && (authorization == null || !authorization.startsWith("DPoP "))) {
                send(exchange, 401, "application/json", UNAUTHORIZED);
                return;
            }
            if ("/oauth2/token".equals(path)) send(exchange, 200, "application/json", TOKEN);
            else if ("/xacml/pep/register".equals(path)) send(exchange, 201, "application/json", REGISTERED);
            else if ("/xacml/pep/heartbeat".equals(path)) send(exchange, 200, "application/json", HEARTBEAT);
            else if ("/xacml/pep/authzen-catalogue".equals(path)) send(exchange, 200, "application/json", CATALOGUE);
            else if ("/xacml/pep/policies".equals(path)) {
                if (policiesUp.get()) send(exchange, 200, "application/json", held);
                else send(exchange, 503, "application/json", NOT_NOW);
            } else if ("/admin-api/pep-audit".equals(path)) send(exchange, 200, "application/json", AUDIT);
            else if ("/access/v1/evaluation".equals(path)) send(exchange, 200, "application/json", PERMIT);
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

    private static byte[] readOnlyPolicy() throws Exception {
        ObjectNode body = JSON.createObjectNode();
        body.put("syncToken", "p1");
        ObjectNode row = body.putArray("policies").addObject();
        row.put("policyId", "orders");
        row.put("kind", "Policy");
        row.put("version", "1.0");
        row.put("isRoot", true);
        row.put("document", READ_ONLY);
        return JSON.writeValueAsBytes(body);
    }

    private static void send(HttpExchange exchange, int status, String type, byte[] body) throws java.io.IOException {
        exchange.getResponseHeaders().set("Content-Type", type);
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static byte[] json(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
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

    private static SamlLogin login() {
        SamlLogin login = new SamlLogin();
        login.nameId = "alice";
        login.attributes.put("uid", List.of("alice"));
        return login;
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
