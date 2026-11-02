// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

/** XML this package reads and writes. A DOCTYPE is refused before the parser sees it. */
public final class Xml {
    public static final String SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
    public static final String SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
    public static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    public static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    public static final String XENC = "http://www.w3.org/2001/04/xmlenc#";
    public static final String XENC11 = "http://www.w3.org/2009/xmlenc11#";
    public static final String SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    public static final String BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    public static final String BINDING_ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
    public static final String BINDING_SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
    public static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    public static final String BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    private static final Pattern DOCTYPE = Pattern.compile("<!DOCTYPE|<!ENTITY", Pattern.CASE_INSENSITIVE);

    private Xml() {}

    public static Document parse(String text, String what) {
        if (DOCTYPE.matcher(text).find()) {
            throw new SamlError("xml", what + " carries a DOCTYPE or an entity declaration, which SAML never needs");
        }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setExpandEntityReferences(false);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            trySet(factory, "http://apache.org/xml/features/disallow-doctype-decl", true);
            trySet(factory, "http://xml.org/sax/features/external-general-entities", false);
            trySet(factory, "http://xml.org/sax/features/external-parameter-entities", false);
            Document document = factory.newDocumentBuilder().parse(new InputSource(new StringReader(text)));
            document.getDocumentElement().normalize();
            return document;
        } catch (SamlError err) {
            throw err;
        } catch (Exception err) {
            throw new SamlError("xml", what + " is not well-formed XML: " + err.getMessage(), err);
        }
    }

    private static void trySet(DocumentBuilderFactory factory, String feature, boolean value) {
        try {
            factory.setFeature(feature, value);
        } catch (Exception ignored) {
            // The JDK parser does not offer every feature. DOCTYPE is already refused by text.
        }
    }

    public static String serialize(Node node) {
        try {
            TransformerFactory factory = TransformerFactory.newInstance();
            var transformer = factory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(node), new StreamResult(writer));
            return writer.toString();
        } catch (Exception err) {
            throw new SamlError("xml", "the message could not be written: " + err.getMessage(), err);
        }
    }

    public static List<Element> children(Element element, String namespace, String local) {
        List<Element> found = new ArrayList<>();
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element child && namespace.equals(child.getNamespaceURI()) && local.equals(child.getLocalName())) {
                found.add(child);
            }
        }
        return found;
    }

    public static Element child(Element element, String namespace, String local) {
        List<Element> found = children(element, namespace, local);
        if (found.size() > 1) {
            throw new SamlError("validation", "<" + element.getLocalName() + "> has more than one <" + local + ">");
        }
        return found.isEmpty() ? null : found.get(0);
    }

    public static List<Element> descendants(Element element, String namespace, String local) {
        List<Element> found = new ArrayList<>();
        walk(element, namespace, local, found);
        return found;
    }

    private static void walk(Element element, String namespace, String local, List<Element> found) {
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element child) {
                if (namespace.equals(child.getNamespaceURI()) && local.equals(child.getLocalName())) found.add(child);
                walk(child, namespace, local, found);
            }
        }
    }

    public static String text(Element element) {
        if (element == null) return "";
        return element.getTextContent().trim();
    }

    public static String attr(Element element, String name) {
        if (element == null || !element.hasAttribute(name)) return null;
        return element.getAttribute(name);
    }

    public static void assertUniqueIds(Document document) {
        Set<String> seen = new LinkedHashSet<>();
        walkIds(document.getDocumentElement(), seen);
    }

    private static void walkIds(Element element, Set<String> seen) {
        for (String name : new String[] {"ID", "Id", "id"}) {
            if (!element.hasAttribute(name)) continue;
            String value = element.getAttribute(name);
            if (value.isEmpty()) continue;
            if (!seen.add(value)) throw new SamlError("signature", "two elements carry the ID " + value);
        }
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element child) walkIds(child, seen);
        }
    }

    public static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;");
    }

    public static String pemBody(String pem) {
        return pem.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "").replaceAll("\\s+", "");
    }

    public static String toPem(String base64) {
        String body = base64.replaceAll("\\s+", "");
        StringBuilder out = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < body.length(); i += 64) out.append(body, i, Math.min(i + 64, body.length())).append('\n');
        return out.append("-----END CERTIFICATE-----\n").toString();
    }
}
