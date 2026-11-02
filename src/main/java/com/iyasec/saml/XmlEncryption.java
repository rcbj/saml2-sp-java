// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.w3c.dom.Element;

/** Decrypting an EncryptedAssertion, EncryptedID or EncryptedAttribute. RSA PKCS#1 v1.5 is refused. */
public final class XmlEncryption {
    private static final String OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    private static final String OAEP = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
    private static final Map<String, CipherSpec> CIPHERS = Map.of(
        "http://www.w3.org/2009/xmlenc11#aes128-gcm", new CipherSpec("aes-128-gcm", true, 16),
        "http://www.w3.org/2009/xmlenc11#aes192-gcm", new CipherSpec("aes-192-gcm", true, 24),
        "http://www.w3.org/2009/xmlenc11#aes256-gcm", new CipherSpec("aes-256-gcm", true, 32),
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc", new CipherSpec("aes-128-cbc", false, 16),
        "http://www.w3.org/2001/04/xmlenc#aes192-cbc", new CipherSpec("aes-192-cbc", false, 24),
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc", new CipherSpec("aes-256-cbc", false, 32)
    );
    private static final Map<String, String> DIGESTS = Map.of(
        "http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1",
        "http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256",
        "http://www.w3.org/2001/04/xmldsig-more#sha384", "SHA-384",
        "http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512"
    );
    private static final Map<String, String> MGFS = Map.of(
        "http://www.w3.org/2009/xmlenc11#mgf1sha1", "SHA-1",
        "http://www.w3.org/2009/xmlenc11#mgf1sha256", "SHA-256",
        "http://www.w3.org/2009/xmlenc11#mgf1sha384", "SHA-384",
        "http://www.w3.org/2009/xmlenc11#mgf1sha512", "SHA-512"
    );

    private record CipherSpec(String name, boolean gcm, int keyLength) {}

    private XmlEncryption() {}

    public static String decryptElement(Element encrypted, PrivateKey key) {
        Element data = Xml.child(encrypted, Xml.XENC, "EncryptedData");
        if (data == null) fail("<" + encrypted.getLocalName() + "> has no EncryptedData");
        Element method = Xml.child(data, Xml.XENC, "EncryptionMethod");
        String alg = method == null ? "" : orEmpty(Xml.attr(method, "Algorithm"));
        CipherSpec cipher = CIPHERS.get(alg);
        if (cipher == null) fail("the content is encrypted with " + (alg.isEmpty() ? "(none)" : alg) + ", which is not supported");
        List<Element> encryptedKeys = Xml.descendants(encrypted, Xml.XENC, "EncryptedKey");
        if (encryptedKeys.isEmpty()) fail("<" + encrypted.getLocalName() + "> carries no EncryptedKey");
        byte[] contentKey = unwrapKey(encryptedKeys.get(0), key);
        if (contentKey.length != cipher.keyLength) {
            fail("the content key is " + contentKey.length + " bytes; " + cipher.name + " needs " + cipher.keyLength);
        }
        Element cipherData = Xml.child(data, Xml.XENC, "CipherData");
        Element cipherValue = cipherData == null ? null : Xml.child(cipherData, Xml.XENC, "CipherValue");
        byte[] blob = b64(cipherValue == null ? "" : cipherValue.getTextContent());
        try {
            if (cipher.gcm) {
                if (blob.length < 12 + 16) fail("the ciphertext is too short");
                Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
                gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(contentKey, "AES"), new GCMParameterSpec(128, slice(blob, 0, 12)));
                return new String(gcm.doFinal(slice(blob, 12, blob.length)), StandardCharsets.UTF_8);
            }
            if (blob.length < 32 || blob.length % 16 != 0) fail("the ciphertext is not a whole number of blocks");
            Cipher cbc = Cipher.getInstance("AES/CBC/NoPadding");
            cbc.init(Cipher.DECRYPT_MODE, new SecretKeySpec(contentKey, "AES"), new IvParameterSpec(slice(blob, 0, 16)));
            byte[] plain = cbc.doFinal(slice(blob, 16, blob.length));
            int pad = plain[plain.length - 1] & 0xff;
            if (pad < 1 || pad > 16) fail("the decrypted content is not padded as XML Encryption pads it");
            return new String(plain, 0, plain.length - pad, StandardCharsets.UTF_8);
        } catch (SamlError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            fail("the content could not be decrypted", err);
            return "";
        }
    }

    private static byte[] unwrapKey(Element encryptedKey, PrivateKey key) {
        Element method = Xml.child(encryptedKey, Xml.XENC, "EncryptionMethod");
        String alg = method == null ? "" : orEmpty(Xml.attr(method, "Algorithm"));
        if (!OAEP_MGF1P.equals(alg) && !OAEP.equals(alg)) {
            fail("the content key is wrapped with " + (alg.isEmpty() ? "(none)" : alg) + "; only RSA-OAEP is accepted");
        }
        Element digestMethod = method == null ? null : Xml.child(method, Xml.DS, "DigestMethod");
        String digestAlg = digestMethod == null ? null : Xml.attr(digestMethod, "Algorithm");
        String digest = digestAlg == null || digestAlg.isEmpty() ? "SHA-1" : DIGESTS.getOrDefault(digestAlg, "");
        if (digest.isEmpty()) fail("the OAEP digest " + digestAlg + " is not supported");
        String mgf = "SHA-1";
        if (OAEP.equals(alg) && method != null) {
            Element mgfEl = Xml.child(method, Xml.XENC11, "MGF");
            String mgfAlg = mgfEl == null ? null : Xml.attr(mgfEl, "Algorithm");
            if (mgfAlg != null && !mgfAlg.isEmpty()) {
                mgf = MGFS.getOrDefault(mgfAlg, "");
                if (mgf.isEmpty()) fail("the OAEP mask generation function " + mgfAlg + " is not supported");
            }
        }
        if (!mgf.equals(digest)) {
            fail("OAEP with digest " + digest + " and MGF1 " + mgf + " is not supported; one hash is used for both");
        }
        List<Element> values = Xml.descendants(encryptedKey, Xml.XENC, "CipherValue");
        String raw = values.isEmpty() ? "" : values.get(0).getTextContent();
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec spec = new OAEPParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            return cipher.doFinal(b64(raw));
        } catch (SamlError err) {
            throw err;
        } catch (Exception err) {
            Caught.error(err);
            fail("the content key could not be unwrapped with this service provider's key", err);
            return new byte[0];
        }
    }

    private static byte[] b64(String value) {
        return Base64.getMimeDecoder().decode(value.replaceAll("\\s+", ""));
    }

    private static byte[] slice(byte[] data, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(data, from, out, 0, out.length);
        return out;
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }

    private static void fail(String message) {
        throw new SamlError("decryption", message);
    }

    private static void fail(String message, Exception cause) {
        throw new SamlError("decryption", message, cause);
    }
}
