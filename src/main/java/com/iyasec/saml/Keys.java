// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Locale;

/** A self-signed certificate for a service provider's signing key. SAML uses it only as a public-key container. */
public final class Keys {
    public record KeyPair(String privateKeyPem, String certificatePem, PrivateKey privateKey, X509Certificate certificate) {
        public String fingerprint256() {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
                StringBuilder out = new StringBuilder();
                for (int i = 0; i < digest.length; i++) {
                    if (i > 0) out.append(':');
                    out.append(String.format("%02X", digest[i]));
                }
                return out.toString();
            } catch (Exception err) {
                throw new SamlError("config", "the certificate fingerprint could not be computed", err);
            }
        }

        public String validTo() {
            var when = certificate.getNotAfter().toInstant().atZone(ZoneOffset.UTC);
            return DateTimeFormatter.ofPattern("MMM dd HH:mm:ss yyyy 'GMT'", Locale.US).format(when).replaceFirst(" 0", "  ");
        }
    }

    private Keys() {}

    public static KeyPair createSelfSigned(String commonName, int days, int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            java.security.KeyPair generated = generator.generateKeyPair();
            X509Certificate certificate = selfSigned((RSAPublicKey) generated.getPublic(), generated.getPrivate(), commonName, days);
            String keyPem = pem("PRIVATE KEY", generated.getPrivate().getEncoded());
            String certPem = pem("CERTIFICATE", certificate.getEncoded());
            return new KeyPair(keyPem, certPem, generated.getPrivate(), certificate);
        } catch (SamlError err) {
            throw err;
        } catch (Exception err) {
            throw new SamlError("config", "the key pair could not be created: " + err.getMessage(), err);
        }
    }

    public static PrivateKey loadPrivateKey(String pem) {
        try {
            String body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(body);
            if (pem.contains("BEGIN RSA PRIVATE KEY")) der = pkcs1ToPkcs8(der);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception err) {
            throw new SamlError("config", "the private key or certificate cannot be read: " + err.getMessage(), err);
        }
    }

    public static X509Certificate loadCertificate(String pem) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        } catch (Exception err) {
            throw new SamlError("config", "the private key or certificate cannot be read: " + err.getMessage(), err);
        }
    }

    public static String certificatePem(X509Certificate certificate) {
        try {
            return pem("CERTIFICATE", certificate.getEncoded());
        } catch (Exception err) {
            throw new SamlError("config", "the certificate could not be written", err);
        }
    }

    public static String privateKeyPem(PrivateKey key) {
        return pem("PRIVATE KEY", key.getEncoded());
    }

    private static X509Certificate selfSigned(RSAPublicKey publicKey, PrivateKey privateKey, String commonName, int days) throws Exception {
        Instant notBefore = Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.SECONDS);
        Instant notAfter = notBefore.plus(days, ChronoUnit.DAYS);
        byte[] name = name(commonName);
        byte[] spki = subjectPublicKeyInfo(publicKey);
        byte[] serial = new byte[8];
        new SecureRandom().nextBytes(serial);
        serial[0] = (byte) (serial[0] & 0x7f);
        byte[] tbs = Der.seq(
            Der.explicit(0, Der.integer(BigInteger.valueOf(2))),
            Der.integer(new BigInteger(serial)),
            algorithm(),
            name,
            Der.seq(Der.utc(notBefore), Der.utc(notAfter)),
            name,
            spki,
            Der.explicit(3, extensions())
        );
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(tbs);
        byte[] signature = signer.sign();
        byte[] certificate = Der.seq(tbs, algorithm(), Der.bitString(signature));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificate));
    }

    private static byte[] algorithm() {
        return Der.seq(Der.oid("1.2.840.113549.1.1.11"), Der.nul());
    }

    private static byte[] name(String commonName) {
        byte[] rdn = Der.seq(Der.oid("2.5.4.3"), Der.utf8(commonName));
        return Der.seq(Der.set(rdn));
    }

    private static byte[] subjectPublicKeyInfo(RSAPublicKey key) {
        byte[] rsa = Der.seq(Der.integer(key.getModulus()), Der.integer(key.getPublicExponent()));
        return Der.seq(Der.seq(Der.oid("1.2.840.113549.1.1.1"), Der.nul()), Der.bitString(rsa));
    }

    private static byte[] extensions() {
        byte[] basic = Der.seq(Der.bool(false));
        byte[] usage = Der.bitString(new byte[] {(byte) 0xa0}, 5);
        return Der.seq(
            Der.seq(Der.oid("2.5.29.19"), Der.bool(true), Der.octet(basic)),
            Der.seq(Der.oid("2.5.29.15"), Der.bool(true), Der.octet(usage))
        );
    }

    private static byte[] pkcs1ToPkcs8(byte[] pkcs1) {
        byte[] alg = Der.seq(Der.oid("1.2.840.113549.1.1.1"), Der.nul());
        return Der.seq(Der.integer(BigInteger.ZERO), alg, Der.octet(pkcs1));
    }

    private static String pem(String kind, byte[] der) {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
        return "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----\n";
    }

    static boolean sameKey(PrivateKey privateKey, X509Certificate certificate) {
        if (!(certificate.getPublicKey() instanceof RSAPublicKey cert)) return false;
        if (privateKey instanceof RSAPrivateCrtKey crt) {
            return crt.getModulus().equals(cert.getModulus()) && crt.getPublicExponent().equals(cert.getPublicExponent());
        }
        try {
            RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                ((RSAPublicKey) certificate.getPublicKey()).getModulus(),
                ((RSAPublicKey) certificate.getPublicKey()).getPublicExponent()));
            return pub.getModulus().equals(cert.getModulus());
        } catch (Exception err) {
            return false;
        }
    }

    /** Small DER writer for the self-signed certificate. No extra cryptography library. */
    static final class Der {
        private Der() {}

        static byte[] seq(byte[]... parts) { return tag(0x30, concat(parts)); }
        static byte[] set(byte[] part) { return tag(0x31, part); }
        static byte[] octet(byte[] part) { return tag(0x04, part); }
        static byte[] nul() { return new byte[] {0x05, 0x00}; }
        static byte[] bool(boolean value) { return new byte[] {0x01, 0x01, (byte) (value ? 0xff : 0x00)}; }
        static byte[] utf8(String value) { return tag(0x0c, value.getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
        static byte[] explicit(int number, byte[] inner) { return tag(0xa0 | number, inner); }

        static byte[] integer(BigInteger value) { return tag(0x02, value.toByteArray()); }

        static byte[] bitString(byte[] payload) { return bitString(payload, 0); }

        static byte[] bitString(byte[] payload, int unused) {
            byte[] body = new byte[payload.length + 1];
            body[0] = (byte) unused;
            System.arraycopy(payload, 0, body, 1, payload.length);
            return tag(0x03, body);
        }

        static byte[] utc(Instant instant) {
            int year = instant.atZone(ZoneOffset.UTC).getYear();
            if (year >= 2050) {
                String text = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC).format(instant);
                return tag(0x18, text.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            }
            String text = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC).format(instant);
            return tag(0x17, text.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        }

        static byte[] oid(String dotted) {
            String[] parts = dotted.split("\\.");
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.write(Integer.parseInt(parts[0]) * 40 + Integer.parseInt(parts[1]));
            for (int i = 2; i < parts.length; i++) base128(body, Integer.parseInt(parts[i]));
            return tag(0x06, body.toByteArray());
        }

        private static void base128(ByteArrayOutputStream out, int value) {
            byte[] stack = new byte[6];
            int n = 0;
            stack[n++] = (byte) (value & 0x7f);
            value >>>= 7;
            while (value > 0) {
                stack[n++] = (byte) ((value & 0x7f) | 0x80);
                value >>>= 7;
            }
            for (int i = n - 1; i >= 0; i--) out.write(stack[i]);
        }

        private static byte[] tag(int tag, byte[] body) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(tag);
            if (body.length < 128) out.write(body.length);
            else {
                int length = body.length;
                byte[] len = BigInteger.valueOf(length).toByteArray();
                int start = len[0] == 0 ? 1 : 0;
                out.write(0x80 | (len.length - start));
                out.write(len, start, len.length - start);
            }
            out.writeBytes(body);
            return out.toByteArray();
        }

        private static byte[] concat(byte[]... parts) {
            int size = 0;
            for (byte[] part : parts) size += part.length;
            byte[] out = new byte[size];
            int at = 0;
            for (byte[] part : parts) {
                System.arraycopy(part, 0, out, at, part.length);
                at += part.length;
            }
            return out;
        }
    }
}
