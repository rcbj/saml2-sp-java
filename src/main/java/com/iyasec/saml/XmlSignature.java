// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/** XML signatures. Exclusive canonicalization is Santuario's; RSA is the JDK's. */
public final class XmlSignature {
    public static final String EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public static final String EXC_C14N_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
    public static final String C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    public static final String C14N_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    public static final String ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

    public static final Map<String, String> SIGNATURE_ALGORITHMS = Map.of(
        RSA_SHA256, "SHA256withRSA",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "SHA384withRSA",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "SHA512withRSA"
    );
    public static final Map<String, String> QUERY_ALGORITHMS = SIGNATURE_ALGORITHMS;
    public static final Map<String, String> DIGEST_ALGORITHMS = Map.of(
        SHA256, "SHA-256",
        "http://www.w3.org/2001/04/xmldsig-more#sha384", "SHA-384",
        "http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512"
    );
    private static final Set<String> TRANSFORMS = Set.of(ENVELOPED, EXC_C14N, EXC_C14N_COMMENTS, C14N, C14N_COMMENTS);
    private static final Set<String> CANONICALIZATIONS = TRANSFORMS.stream().filter(item -> !item.equals(ENVELOPED)).collect(java.util.stream.Collectors.toUnmodifiableSet());

    static {
        Init.init();
    }

    private XmlSignature() {}

    public static boolean isSigned(Element element) {
        return !Xml.children(element, Xml.DS, "Signature").isEmpty();
    }

    public static String verifySigned(Element element, List<X509Certificate> certs, String what) {
        Element signature = Xml.child(element, Xml.DS, "Signature");
        if (signature == null) return null;
        String elementId = Xml.attr(element, "ID");
        if (elementId == null || elementId.isEmpty()) {
            throw new SamlError("signature", what + " is signed but has no ID for the signature to refer to");
        }
        Element signedInfo = Xml.child(signature, Xml.DS, "SignedInfo");
        if (signedInfo == null) throw new SamlError("signature", what + "'s signature has no SignedInfo");
        String c14nAlg = algorithm(signedInfo, "CanonicalizationMethod");
        if (!CANONICALIZATIONS.contains(c14nAlg)) {
            throw new SamlError("signature", what + "'s signature uses the canonicalization " + (c14nAlg.isEmpty() ? "(none)" : c14nAlg) + ", which is refused");
        }
        String sigAlg = algorithm(signedInfo, "SignatureMethod");
        String javaAlg = SIGNATURE_ALGORITHMS.get(sigAlg);
        if (javaAlg == null) {
            throw new SamlError("signature", what + "'s signature uses " + (sigAlg.isEmpty() ? "(none)" : sigAlg) + ", which is refused (SHA-1 and non-RSA algorithms are not accepted)");
        }
        List<Element> refs = Xml.children(signedInfo, Xml.DS, "Reference");
        if (refs.size() != 1) {
            throw new SamlError("signature", what + "'s signature has " + refs.size() + " references; exactly one is accepted");
        }
        Element ref = refs.get(0);
        String uri = Xml.attr(ref, "URI");
        if (uri == null || !uri.equals("#" + elementId)) {
            throw new SamlError("signature", what + "'s signature refers to " + (uri == null || uri.isEmpty() ? "(nothing)" : uri) + ", not to " + what + " itself (#" + elementId + ")");
        }
        String digestAlg = algorithm(ref, "DigestMethod");
        String digestName = DIGEST_ALGORITHMS.get(digestAlg);
        if (digestName == null) {
            throw new SamlError("signature", what + "'s signature digests with " + (digestAlg.isEmpty() ? "(none)" : digestAlg) + ", which is refused");
        }
        Element transforms = Xml.child(ref, Xml.DS, "Transforms");
        List<Element> transformEls = transforms == null ? List.of() : Xml.children(transforms, Xml.DS, "Transform");
        for (Element transform : transformEls) {
            String alg = Xml.attr(transform, "Algorithm");
            if (alg == null || !TRANSFORMS.contains(alg)) {
                throw new SamlError("signature", what + "'s signature uses the transform " + (alg == null || alg.isEmpty() ? "(none)" : alg) + ", which is refused");
            }
        }
        if (certs == null || certs.isEmpty()) {
            throw new SamlError("signature", "no signing certificate is known for the identity provider, so " + what + " cannot be verified");
        }
        byte[] reference = applyTransforms(element, signature, transformEls);
        byte[] got;
        try {
            got = Base64.getMimeDecoder().decode(compact(Xml.child(ref, Xml.DS, "DigestValue")));
        } catch (Exception err) {
            throw new SamlError("signature", what + "'s signature does not verify against the identity provider's certificate: the digest is not base64", err);
        }
        byte[] want = digest(digestName, reference);
        if (!MessageDigest.isEqual(got, want)) {
            throw new SamlError("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
        }
        Element method = Xml.child(signedInfo, Xml.DS, "CanonicalizationMethod");
        String prefixes = method == null ? null : inclusive(method);
        byte[] signedBytes = canonicalize(signedInfo, c14nAlg, prefixes);
        byte[] sigBytes;
        try {
            sigBytes = Base64.getMimeDecoder().decode(compact(Xml.child(signature, Xml.DS, "SignatureValue")));
        } catch (Exception err) {
            throw new SamlError("signature", what + "'s signature does not verify against the identity provider's certificate: the signature value is not base64", err);
        }
        boolean verified = false;
        for (X509Certificate cert : certs) {
            if (Bindings.verify(cert, javaAlg, signedBytes, sigBytes)) {
                verified = true;
                break;
            }
        }
        if (!verified) {
            throw new SamlError("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
        }
        return signedContent(element);
    }

    public static String signEnveloped(String xml, String elementId, PrivateKey key, X509Certificate certificate) {
        Document document = Xml.parse(xml, "the message to sign");
        Element target = elementById(document.getDocumentElement(), elementId);
        if (target == null) throw new SamlError("signature", "no element has ID " + elementId);
        byte[] reference = canonicalize(target, EXC_C14N, null);
        String digest = Base64.getEncoder().encodeToString(digest("SHA-256", reference));
        Element signature = signatureElement(document, elementId, digest, certificate);
        Element issuer = null;
        for (Element candidate : Xml.children(target, Xml.SAML, "Issuer")) {
            issuer = candidate;
            break;
        }
        if (issuer != null) target.insertBefore(signature, issuer.getNextSibling());
        else target.insertBefore(signature, target.getFirstChild());
        Element signedInfo = Xml.children(signature, Xml.DS, "SignedInfo").get(0);
        byte[] signedBytes = canonicalize(signedInfo, EXC_C14N, null);
        Xml.children(signature, Xml.DS, "SignatureValue").get(0).setTextContent(
            Base64.getEncoder().encodeToString(Bindings.sign(key, "SHA256withRSA", signedBytes)));
        return Xml.serialize(document.getDocumentElement());
    }

    private static String signedContent(Element element) {
        Node removed = null;
        Node anchor = null;
        for (Element signature : Xml.children(element, Xml.DS, "Signature")) {
            anchor = signature.getNextSibling();
            removed = signature;
            element.removeChild(signature);
            break;
        }
        try {
            return new String(canonicalize(element, EXC_C14N, null), StandardCharsets.UTF_8);
        } finally {
            if (removed != null) element.insertBefore(removed, anchor);
        }
    }

    private static byte[] applyTransforms(Element element, Element signature, List<Element> transforms) {
        boolean detached = false;
        Node anchor = signature.getNextSibling();
        if (!transforms.isEmpty() && ENVELOPED.equals(orEmpty(Xml.attr(transforms.get(0), "Algorithm")))) {
            signature.getParentNode().removeChild(signature);
            detached = true;
        }
        try {
            Element node = element;
            byte[] data = null;
            int start = detached ? 1 : 0;
            if (transforms.isEmpty()) return canonicalize(element, C14N, null);
            for (int index = start; index < transforms.size(); index++) {
                Element transform = transforms.get(index);
                String alg = orEmpty(Xml.attr(transform, "Algorithm"));
                if (data != null) {
                    node = Xml.parse(new String(data, StandardCharsets.UTF_8), "the transformed signature reference").getDocumentElement();
                    data = null;
                }
                if (ENVELOPED.equals(alg)) {
                    Element copied = Xml.parse(Xml.serialize(node), "the enveloped transform").getDocumentElement();
                    for (Element sig : new ArrayList<>(Xml.children(copied, Xml.DS, "Signature"))) {
                        if (compact(Xml.child(sig, Xml.DS, "SignatureValue")).equals(compact(Xml.child(signature, Xml.DS, "SignatureValue")))
                            || sig.getParentNode() == copied) {
                            sig.getParentNode().removeChild(sig);
                            break;
                        }
                    }
                    node = copied;
                    continue;
                }
                if (CANONICALIZATIONS.contains(alg)) {
                    data = canonicalize(node, alg, inclusive(transform));
                    node = null;
                    if (index == transforms.size() - 1) return data;
                    continue;
                }
                throw new SamlError("signature", "the signature uses the transform " + (alg.isEmpty() ? "(none)" : alg) + ", which is refused");
            }
            if (data != null) return data;
            return canonicalize(node, C14N, null);
        } finally {
            if (detached && signature.getParentNode() == null) element.insertBefore(signature, anchor);
        }
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String inclusive(Element transform) {
        for (Node node = transform.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element child && "InclusiveNamespaces".equals(child.getLocalName())) {
                String list = child.getAttribute("PrefixList");
                return list == null || list.isEmpty() ? null : list;
            }
        }
        return null;
    }

    static byte[] canonicalize(Node node, String algorithm, String inclusive) {
        try {
            Canonicalizer canonicalizer = Canonicalizer.getInstance(algorithm);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            if (inclusive == null || inclusive.isEmpty()) canonicalizer.canonicalizeSubtree(node, out);
            else canonicalizer.canonicalizeSubtree(node, inclusive, out);
            return out.toByteArray();
        } catch (SamlError err) {
            throw err;
        } catch (Exception err) {
            throw new SamlError("signature", "the message could not be canonicalized: " + err.getMessage(), err);
        }
    }

    private static Element elementById(Element root, String elementId) {
        if (matches(root, elementId)) return root;
        for (Node node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element child) {
                Element found = elementById(child, elementId);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static boolean matches(Element element, String elementId) {
        for (String name : new String[] {"ID", "Id", "id"}) {
            if (element.hasAttribute(name) && elementId.equals(element.getAttribute(name))) return true;
        }
        return false;
    }

    private static String algorithm(Element parent, String local) {
        Element found = Xml.child(parent, Xml.DS, local);
        if (found == null) return "";
        String value = Xml.attr(found, "Algorithm");
        return value == null ? "" : value;
    }

    private static String compact(Element element) {
        if (element == null) return "";
        return element.getTextContent().replaceAll("\\s+", "");
    }

    private static byte[] digest(String algorithm, byte[] data) {
        try {
            return MessageDigest.getInstance(algorithm).digest(data);
        } catch (Exception err) {
            throw new SamlError("signature", "the digest could not be computed", err);
        }
    }

    private static Element signatureElement(Document document, String elementId, String digest, X509Certificate certificate) {
        Element signature = el(document, "Signature");
        Element signedInfo = el(document, "SignedInfo");
        signature.appendChild(signedInfo);
        Element c14n = el(document, "CanonicalizationMethod");
        c14n.setAttribute("Algorithm", EXC_C14N);
        signedInfo.appendChild(c14n);
        Element method = el(document, "SignatureMethod");
        method.setAttribute("Algorithm", RSA_SHA256);
        signedInfo.appendChild(method);
        Element ref = el(document, "Reference");
        ref.setAttribute("URI", "#" + elementId);
        signedInfo.appendChild(ref);
        Element transforms = el(document, "Transforms");
        ref.appendChild(transforms);
        Element enveloped = el(document, "Transform");
        enveloped.setAttribute("Algorithm", ENVELOPED);
        transforms.appendChild(enveloped);
        Element exc = el(document, "Transform");
        exc.setAttribute("Algorithm", EXC_C14N);
        transforms.appendChild(exc);
        Element digestMethod = el(document, "DigestMethod");
        digestMethod.setAttribute("Algorithm", SHA256);
        ref.appendChild(digestMethod);
        Element digestValue = el(document, "DigestValue");
        digestValue.setTextContent(digest);
        ref.appendChild(digestValue);
        signature.appendChild(el(document, "SignatureValue"));
        Element keyInfo = el(document, "KeyInfo");
        Element data = el(document, "X509Data");
        Element cert = el(document, "X509Certificate");
        cert.setTextContent(Xml.pemBody(Keys.certificatePem(certificate)));
        data.appendChild(cert);
        keyInfo.appendChild(data);
        signature.appendChild(keyInfo);
        return signature;
    }

    private static Element el(Document document, String local) {
        return document.createElementNS(Xml.DS, "ds:" + local);
    }

}
