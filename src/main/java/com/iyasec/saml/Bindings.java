// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/** HTTP-Redirect and HTTP-POST encodings (SAML 2.0 Bindings, sections 3.4 and 3.5). */
public final class Bindings {
    public static final int MAX_INFLATED = 1024 * 1024;
    private static final String URI_SAFE = "-_.!~*'()";

    private Bindings() {}

    public static String uriEscape(String value) {
        StringBuilder out = new StringBuilder();
        for (byte bite : value.getBytes(StandardCharsets.UTF_8)) {
            int c = bite & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || URI_SAFE.indexOf(c) >= 0) {
                out.append((char) c);
            } else {
                out.append('%').append(String.format("%02X", c));
            }
        }
        return out.toString();
    }

    public static String uriUnescape(String value) {
        String text = value.replace("+", "%20");
        if (text.matches("(?s).*((?<!%)%(?![0-9A-Fa-f]{2})).*" ) || badPercent(text)) {
            throw new SamlError("binding", "the query string is not validly percent-encoded");
        }
        try {
            return decode(text);
        } catch (IllegalArgumentException err) {
            throw new SamlError("binding", "the query string is not validly percent-encoded", err);
        }
    }

    private static boolean badPercent(String text) {
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) != '%') continue;
            if (i + 2 >= text.length()) return true;
            if (Character.digit(text.charAt(i + 1), 16) < 0 || Character.digit(text.charAt(i + 2), 16) < 0) return true;
            i += 2;
        }
        return false;
    }

    private static String decode(String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '%') {
                out.write(Integer.parseInt(text.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                out.write((byte) c);
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    public static byte[] deflateRaw(byte[] data) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(data);
        deflater.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        while (!deflater.finished()) {
            int n = deflater.deflate(buf);
            if (n > 0) out.write(buf, 0, n);
        }
        deflater.end();
        return out.toByteArray();
    }

    public static byte[] inflateRaw(byte[] data) {
        Inflater inflater = new Inflater(true);
        inflater.setInput(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        try {
            while (!inflater.finished()) {
                int n = inflater.inflate(buf);
                if (n == 0 && inflater.needsInput()) break;
                if (n > 0) out.write(buf, 0, n);
                if (out.size() > MAX_INFLATED) throw new SamlError("binding", "the message inflates past the limit");
            }
        } catch (DataFormatException err) {
            throw new SamlError("binding", "the message inflates past the limit", err);
        } finally {
            inflater.end();
        }
        if (out.size() > MAX_INFLATED) throw new SamlError("binding", "the message inflates past the limit");
        return out.toByteArray();
    }

    public static String redirectQuery(String param, String xml, String relayState, PrivateKey key) {
        String encoded = Base64.getEncoder().encodeToString(deflateRaw(xml.getBytes(StandardCharsets.UTF_8)));
        StringBuilder signed = new StringBuilder();
        signed.append(param).append('=').append(uriEscape(encoded));
        if (relayState != null) signed.append("&RelayState=").append(uriEscape(relayState));
        signed.append("&SigAlg=").append(uriEscape(XmlSignature.RSA_SHA256));
        String signature = Base64.getEncoder().encodeToString(sign(key, "SHA256withRSA", signed.toString().getBytes(StandardCharsets.UTF_8)));
        return signed + "&Signature=" + uriEscape(signature);
    }

    public static Map<String, Object> readRedirect(String rawQuery, String param, List<X509Certificate> certs) {
        Map<String, String> raw = new LinkedHashMap<>();
        String query = rawQuery.startsWith("?") ? rawQuery.substring(1) : rawQuery;
        for (String pair : query.split("&", -1)) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String name = uriUnescape(eq < 0 ? pair : pair.substring(0, eq));
            if (raw.containsKey(name)) throw new SamlError("binding", "the query string carries " + name + " twice");
            raw.put(name, eq < 0 ? "" : pair.substring(eq + 1));
        }
        String message = raw.get(param);
        if (message == null) throw new SamlError("binding", "the query string carries no " + param);
        String xml;
        try {
            xml = new String(inflateRaw(Base64.getDecoder().decode(uriUnescape(message))), StandardCharsets.UTF_8);
        } catch (SamlError err) {
            throw err;
        } catch (Exception err) {
            throw new SamlError("binding", param + " is not a DEFLATE-encoded message", err);
        }
        String relay = raw.containsKey("RelayState") ? uriUnescape(raw.get("RelayState")) : null;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("xml", xml);
        out.put("relayState", relay);
        if (!raw.containsKey("Signature")) {
            out.put("signed", false);
            return out;
        }
        String sigAlg = uriUnescape(raw.getOrDefault("SigAlg", ""));
        String javaAlg = XmlSignature.QUERY_ALGORITHMS.get(sigAlg);
        if (javaAlg == null) {
            throw new SamlError("signature", "the query is signed with " + (sigAlg.isEmpty() ? "(no SigAlg)" : sigAlg) + ", which is refused");
        }
        StringBuilder signed = new StringBuilder();
        signed.append(param).append('=').append(message);
        if (raw.containsKey("RelayState")) signed.append("&RelayState=").append(raw.get("RelayState"));
        signed.append("&SigAlg=").append(raw.getOrDefault("SigAlg", ""));
        byte[] data = signed.toString().getBytes(StandardCharsets.UTF_8);
        byte[] sigBytes;
        try {
            sigBytes = Base64.getDecoder().decode(uriUnescape(raw.get("Signature")));
        } catch (Exception err) {
            throw new SamlError("signature", "the query string signature does not verify against the identity provider's certificate", err);
        }
        for (X509Certificate cert : certs) {
            if (verify(cert, javaAlg, data, sigBytes)) {
                out.put("signed", true);
                return out;
            }
        }
        throw new SamlError("signature", "the query string signature does not verify against the identity provider's certificate");
    }

    public static String readPost(String value, String param) {
        String compact = value.replaceAll("\\s+", "");
        if (compact.isEmpty() || !compact.matches("[A-Za-z0-9+/]+={0,2}")) {
            throw new SamlError("binding", param + " is not base64");
        }
        return new String(Base64.getDecoder().decode(compact), StandardCharsets.UTF_8);
    }

    public static String postFormHtml(String action, Map<String, String> fields, String nonce, String title) {
        StringBuilder inputs = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> field : fields.entrySet()) {
            if (!first) inputs.append("\n      ");
            first = false;
            inputs.append("<input type=\"hidden\" name=\"").append(Xml.escape(field.getKey())).append("\" value=\"")
                .append(Xml.escape(field.getValue())).append("\">");
        }
        String script = nonce != null && !nonce.isEmpty()
            ? "\n    <script nonce=\"" + Xml.escape(nonce) + "\">document.forms[0].submit();</script>"
            : "";
        return "<!doctype html>\n<html lang=\"en\">\n  <head><meta charset=\"utf-8\"><title>"
            + Xml.escape(title == null || title.isEmpty() ? "Signing in" : title) + "</title></head>\n  <body>\n    <form method=\"post\" action=\""
            + Xml.escape(action) + "\">\n      " + inputs + "\n      <noscript><p>Your browser is not running scripts. Press Continue to go on.</p></noscript>\n"
            + "      <button type=\"submit\">Continue</button>\n    </form>" + script + "\n  </body>\n</html>\n";
    }

    static byte[] sign(PrivateKey key, String algorithm, byte[] data) {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(key);
            signature.update(data);
            return signature.sign();
        } catch (SamlError err) {
            throw err;
        } catch (Exception err) {
            throw new SamlError("signature", "the signature could not be produced: " + err.getMessage(), err);
        }
    }

    static boolean verify(X509Certificate cert, String algorithm, byte[] data, byte[] sig) {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(cert.getPublicKey());
            signature.update(data);
            return signature.verify(sig);
        } catch (Exception err) {
            return false;
        }
    }
}
