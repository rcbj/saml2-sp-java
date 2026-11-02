// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.iyasec.saml.ssf.SignalsReceiver;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * Plain http is refused for every fetch (metadata, ArtifactResolve, the
 * Shared Signals transmitter) unless the host is loopback, before any
 * connection is opened, and the refusal names only the scheme and host.
 */
class PlainHttpTest {
    private static final String REFUSED = "is refused: plain http is allowed only to a loopback host";

    private static StubIdp.Ars ars;
    private static HttpServer server;
    private static final AtomicInteger hits = new AtomicInteger();
    private static String origin;

    @BeforeAll
    static void up() throws Exception {
        ars = StubIdp.startArs();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/md", exchange -> {
            hits.incrementAndGet();
            byte[] body = StubIdp.idpMetadata(null).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("content-type", "application/samlmetadata+xml");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/away", exchange -> {
            hits.incrementAndGet();
            exchange.getResponseHeaders().set("location", "http://example.com/md");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.createContext("/ssf", exchange -> {
            hits.incrementAndGet();
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });
        server.start();
        origin = "127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void down() {
        if (ars != null) ars.close();
        if (server != null) server.stop(0);
    }

    @Test
    void refusesPlainHttpMetadataOffLoopback() {
        refused(() -> ServiceProvider.create(config("http://example.com/saml2/metadata?token=s3cret", null)), "metadata", "http://example.com");
    }

    @Test
    void refusesAPlainHttpArtifactResolutionServiceOffLoopback() {
        refused(() -> resolve("http://example.com/saml2/ars"), "artifact", "http://example.com");
    }

    @Test
    void refusesAPlainHttpTransmitterOffLoopback() {
        refused(() -> receiver("http://example.com/ssf").start(), "ssf", "http://example.com");
    }

    @Test
    void refusesBeforeConnecting() throws Exception {
        // On Linux http://0.0.0.0:<port> reaches a listener on 127.0.0.1, so
        // nothing in this listener's backlog proves no connection was opened.
        try (ServerSocket listener = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            String plain = "http://0.0.0.0:" + listener.getLocalPort();
            refused(() -> ServiceProvider.create(config(plain + "/md", null)), "metadata", plain);
            refused(() -> resolve(plain + "/ars"), "artifact", plain);
            refused(() -> receiver(plain).start(), "ssf", plain);
            listener.setSoTimeout(300);
            assertThrows(SocketTimeoutException.class, listener::accept, "a refused fetch opened a connection");
        }
    }

    @Test
    void userinfoIsNeverLoopbackAndNeverShown() {
        int before = hits.get();
        SamlError err = refused(() -> ServiceProvider.create(config("http://alice:s3cret@" + origin + "/md", null)), "metadata", "http://" + origin);
        assertFalse(err.getMessage().contains("s3cret"), err.getMessage());
        assertFalse(err.getMessage().contains("alice"), err.getMessage());
        refused(() -> ServiceProvider.create(config("http://localhost:80@example.com/md", null)), "metadata", "http://example.com");
        assertEquals(before, hits.get());
    }

    @Test
    void refusesARedirectToPlainHttpOffLoopback() {
        refused(() -> ServiceProvider.create(config("http://" + origin + "/away", null)), "metadata", "http://example.com");
    }

    @Test
    void plainHttpToLoopbackStillWorks() {
        int port = server.getAddress().getPort();
        assertEquals(StubIdp.IDP_ENTITY, ServiceProvider.create(config("http://127.0.0.1:" + port + "/md", null)).idp().entityId);
        assertEquals(StubIdp.IDP_ENTITY, ServiceProvider.create(config("http://localhost:" + port + "/md", null)).idp().entityId);
        String arsLocalhost = ars.url.replace("127.0.0.1", "localhost");
        for (String location : new String[] {ars.url, arsLocalhost}) {
            ServiceProvider sp = ServiceProvider.create(config(null, location));
            String artifact = StubIdp.artifactFor(StubIdp.IDP_ENTITY);
            ars.put(artifact, StubIdp.responseXml(Map.of("inResponseTo", "_r")));
            assertEquals("artifact", sp.acs("GET", "/saml/acs?SAMLart=" + URLEncoder.encode(artifact, StandardCharsets.UTF_8), null, "_r").binding);
        }
        for (String host : new String[] {"127.0.0.1", "localhost"}) {
            int before = hits.get();
            SamlError err = assertThrows(SamlError.class, () -> receiver("http://" + host + ":" + port + "/ssf").start());
            assertEquals("ssf", err.code);
            assertFalse(err.getMessage().contains(REFUSED), err.getMessage());
            assertTrue(hits.get() > before, "the transmitter on " + host + " was not reached");
        }
    }

    @Test
    void httpsToAnUnreachableHostIsAConnectionErrorNotThisRefusal() throws Exception {
        int closed;
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            closed = probe.getLocalPort();
        }
        String https = "https://127.0.0.1:" + closed;
        for (Executable fn : new Executable[] {
            () -> ServiceProvider.create(config(https + "/md", null)),
            () -> resolve(https + "/ars"),
            () -> receiver(https).start(),
        }) {
            SamlError err = assertThrows(SamlError.class, fn);
            assertFalse(err.getMessage().contains(REFUSED), err.getMessage());
            assertTrue(err.getMessage().startsWith(https), err.getMessage());
        }
    }

    private static void resolve(String arsUrl) {
        ServiceProvider sp = ServiceProvider.create(config(null, arsUrl));
        String artifact = StubIdp.artifactFor(StubIdp.IDP_ENTITY);
        sp.acs("GET", "/saml/acs?SAMLart=" + URLEncoder.encode(artifact, StandardCharsets.UTF_8), null, "_r");
    }

    private static SignalsReceiver receiver(String transmitter) {
        return new SignalsReceiver(transmitter, (ids, event) -> { }).log(new SignalsReceiver.Log() {
            public void info(String message) {}
            public void warn(String message) {}
            public void error(String message) {}
        });
    }

    private static SamlError refused(Executable fn, String code, String shown) {
        SamlError err = assertThrows(SamlError.class, fn);
        assertEquals(code, err.code, err.getMessage());
        assertTrue(err.getMessage().startsWith(shown + " " + REFUSED), err.getMessage());
        assertFalse(err.getMessage().contains("s3cret"), err.getMessage());
        assertFalse(err.getMessage().contains("/md") || err.getMessage().contains("/ars") || err.getMessage().contains("/ssf"), err.getMessage());
        return err;
    }

    private static Map<String, Object> config(String metadataUrl, String arsUrl) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("entityId", StubIdp.SP_ENTITY);
        out.put("acsUrl", StubIdp.ACS);
        out.put("privateKey", StubIdp.SP_KEY);
        out.put("certificate", StubIdp.SP_CERT);
        out.put("idpMetadata", metadataUrl != null ? metadataUrl : StubIdp.idpMetadata(arsUrl));
        return out;
    }
}
