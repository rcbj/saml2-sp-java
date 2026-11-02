// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.io.ByteArrayInputStream;
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
        try {
            HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(TIMEOUT).followRedirects(HttpClient.Redirect.NORMAL);
            if (url.startsWith("https://")) builder.sslContext(ssl(tls == null ? Map.of() : tls));
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(TIMEOUT);
            if (headers != null) headers.forEach(request::header);
            if (body == null) request.method(method, HttpRequest.BodyPublishers.noBody());
            else request.method(method, HttpRequest.BodyPublishers.ofString(body));
            HttpResponse<byte[]> response = builder.build().send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            byte[] bytes = response.body() == null ? new byte[0] : response.body();
            if (bytes.length > MAX_BYTES) throw new SamlError(code, url + " answered more than " + MAX_BYTES + " bytes");
            String type = response.headers().firstValue("content-type").orElse("");
            return new Answer(response.statusCode(), type, new String(bytes, StandardCharsets.UTF_8));
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
