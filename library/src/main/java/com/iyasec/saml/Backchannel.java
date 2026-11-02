// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** The back channel. TLS is verified, and an extra CA is added to the default trust anchors. */
public final class Backchannel {
    public static final int MAX_BYTES = 2 * 1024 * 1024;
    public static final Duration TIMEOUT = Duration.ofSeconds(15);

    public record Answer(int status, String contentType, String body) {}

    private Backchannel() {}

    public static Answer send(String url, String method, Map<String, String> headers, String body, Map<String, String> tls, String code) {
        if (!(url.startsWith("https://") || url.startsWith("http://"))) throw new SamlError(code, url + " is not an http(s) URL");
        // Every fetch this library makes comes through here: the identity
        // provider's metadata (its signing keys), the ArtifactResolve (the
        // signed request out, the assertion back) and the Shared Signals
        // transmitter (SETs and the bearer token). None of them may travel in
        // the clear off this machine, so plain http is refused before any DNS
        // lookup or connection unless the host is loopback, and so is every
        // redirect, which is why redirects are followed here, not by the client.
        URI target;
        try {
            target = URI.create(url);
        } catch (IllegalArgumentException err) {
            Caught.error(err);
            throw new SamlError(code, url + ": " + err.getMessage(), err);
        }
        refusePlainHttpOffLoopback(target, code);
        try {
            String currentMethod = method;
            String currentBody = body;
            for (int hop = 0; ; hop++) {
                HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(TIMEOUT).followRedirects(HttpClient.Redirect.NEVER);
                if ("https".equalsIgnoreCase(target.getScheme())) builder.sslContext(ssl(tls == null ? Map.of() : tls));
                HttpRequest.Builder request = HttpRequest.newBuilder(target).timeout(TIMEOUT);
                if (headers != null) headers.forEach(request::header);
                if (currentBody == null) request.method(currentMethod, HttpRequest.BodyPublishers.noBody());
                else request.method(currentMethod, HttpRequest.BodyPublishers.ofString(currentBody));
                HttpResponse<byte[]> response = builder.build().send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
                int status = response.statusCode();
                var location = response.headers().firstValue("location");
                if (REDIRECTS.contains(status) && location.isPresent() && hop < MAX_REDIRECTS) {
                    URI next = target.resolve(location.get());
                    String scheme = String.valueOf(next.getScheme()).toLowerCase();
                    // As HttpClient.Redirect.NORMAL did: never from https down to
                    // http, and never to anything but http(s); the 3xx is the answer.
                    boolean downgrade = "https".equalsIgnoreCase(target.getScheme()) && "http".equals(scheme);
                    if (!downgrade && ("http".equals(scheme) || "https".equals(scheme))) {
                        refusePlainHttpOffLoopback(next, code);
                        // As the JDK's redirect filter: 303, and 301/302 after a POST, become a GET.
                        if (status == 303 && !"HEAD".equals(currentMethod) || (status == 301 || status == 302) && "POST".equals(currentMethod)) {
                            currentMethod = "GET";
                            currentBody = null;
                        }
                        target = next;
                        continue;
                    }
                }
                byte[] bytes = response.body() == null ? new byte[0] : response.body();
                if (bytes.length > MAX_BYTES) throw new SamlError(code, url + " answered more than " + MAX_BYTES + " bytes");
                String type = response.headers().firstValue("content-type").orElse("");
                return new Answer(status, type, new String(bytes, StandardCharsets.UTF_8));
            }
        } catch (SamlError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            String message = String.valueOf(err.getMessage()).toLowerCase();
            if (message.contains("timed out") || message.contains("timeout")) {
                throw new SamlError(code, url + " did not answer within " + TIMEOUT.toSeconds() + " s", err);
            }
            throw new SamlError(code, url + ": " + err.getMessage(), err);
        }
    }

    private static final java.util.Set<Integer> REDIRECTS = java.util.Set.of(301, 302, 303, 307, 308);
    private static final int MAX_REDIRECTS = 5;

    /**
     * Throws unless a plain http URI names a loopback host: 127.0.0.0/8, ::1
     * or the name localhost, where the bytes never leave the machine. A URI
     * with userinfo is never loopback, so "http://localhost:80@host/" cannot
     * pass as localhost. Nothing here resolves a name. The message names the
     * scheme and host[:port] only: never userinfo, path, query or a secret.
     */
    static void refusePlainHttpOffLoopback(URI uri, String code) {
        if (!"http".equalsIgnoreCase(uri.getScheme())) return;
        String host = uri.getHost();
        if (uri.getRawUserInfo() == null && host != null && isLoopbackHost(host)) return;
        String shown = host == null ? "(no host)" : host + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
        throw new SamlError(code, "http://" + shown + " is refused: plain http is allowed only to a loopback host (127.0.0.0/8, ::1, localhost); use https");
    }

    static boolean isLoopbackHost(String host) {
        if ("localhost".equalsIgnoreCase(host)) return true;
        if (host.matches("127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) {
            for (String part : host.split("\\.")) if (Integer.parseInt(part) > 255) return false;
            return true;
        }
        if (host.startsWith("[") && host.endsWith("]")) {
            String literal = host.substring(1, host.length() - 1);
            if (!literal.matches("[0-9A-Fa-f:.]+")) return false;
            try {
                // A bracketed IPv6 literal: parsed, never looked up.
                InetAddress address = InetAddress.getByName(literal);
                return address instanceof java.net.Inet6Address && address.isLoopbackAddress();
            } catch (Exception err) {
                Caught.error(err);
                return false;
            }
        }
        return false;
    }

    private static SSLContext ssl(Map<String, String> tls) throws Exception {
        TrustManagerFactory base = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        base.init((KeyStore) null);
        X509TrustManager fallback = (X509TrustManager) base.getTrustManagers()[0];
        X509TrustManager extra = fallback;
        if (tls.get("ca") != null) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            var certificates = factory.generateCertificates(new ByteArrayInputStream(tls.get("ca").getBytes(StandardCharsets.US_ASCII)));
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            int index = 0;
            for (Certificate certificate : certificates) store.setCertificateEntry("extra-" + index++, certificate);
            TrustManagerFactory added = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            added.init(store);
            X509TrustManager only = (X509TrustManager) added.getTrustManagers()[0];
            extra = new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String auth) throws java.security.cert.CertificateException {
                    fallback.checkClientTrusted(chain, auth);
                }
                public void checkServerTrusted(X509Certificate[] chain, String auth) throws java.security.cert.CertificateException {
                    try { fallback.checkServerTrusted(chain, auth); }
                    catch (java.security.cert.CertificateException err) { only.checkServerTrusted(chain, auth); }
                }
                public X509Certificate[] getAcceptedIssuers() {
                    return concat(fallback.getAcceptedIssuers(), only.getAcceptedIssuers());
                }
            };
        }
        KeyManagerFactory keys = null;
        if (tls.get("cert") != null && tls.get("key") != null) {
            X509Certificate certificate = Keys.loadCertificate(tls.get("cert"));
            var privateKey = Keys.loadPrivateKey(tls.get("key"));
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            store.setKeyEntry("sp", privateKey, new char[0], new Certificate[] {certificate});
            keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(store, new char[0]);
        }
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys == null ? null : keys.getKeyManagers(), new TrustManager[] {extra}, new SecureRandom());
        return context;
    }

    private static X509Certificate[] concat(X509Certificate[] left, X509Certificate[] right) {
        X509Certificate[] out = new X509Certificate[left.length + right.length];
        System.arraycopy(left, 0, out, 0, left.length);
        System.arraycopy(right, 0, out, left.length, right.length);
        return out;
    }
}
