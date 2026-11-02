// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.w3c.dom.Element;

/** Identity-provider metadata in, and this service provider's metadata out. */
public final class Metadata {
    public static final List<String> ENCRYPTION_METHODS = List.of(
        "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
    );

    public static final class IdpMetadata {
        public final String entityId;
        public final Map<String, String> ssoUrls;
        public final Map<Integer, String> artifactResolutionServices;
        public final List<X509Certificate> signingCertificates;
        public final boolean wantAuthnRequestsSigned;

        public IdpMetadata(String entityId, Map<String, String> ssoUrls, Map<Integer, String> artifactResolutionServices,
                           List<X509Certificate> signingCertificates, boolean wantAuthnRequestsSigned) {
            this.entityId = entityId;
            this.ssoUrls = ssoUrls;
            this.artifactResolutionServices = artifactResolutionServices;
            this.signingCertificates = signingCertificates;
            this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
        }
    }

    private Metadata() {}

    public static IdpMetadata readIdpMetadata(String xml, String entityId) {
        Element root = Xml.parse(xml, "the identity provider metadata").getDocumentElement();
        Element entity = null;
        if (Xml.MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName())) {
            entity = root;
        } else if (Xml.MD.equals(root.getNamespaceURI()) && "EntitiesDescriptor".equals(root.getLocalName())) {
            List<Element> all = new ArrayList<>();
            for (Element candidate : Xml.descendants(root, Xml.MD, "EntityDescriptor")) {
                if (!Xml.descendants(candidate, Xml.MD, "IDPSSODescriptor").isEmpty()) all.add(candidate);
            }
            if (entityId != null && !entityId.isEmpty()) {
                for (Element candidate : all) {
                    if (entityId.equals(Xml.attr(candidate, "entityID"))) entity = candidate;
                }
            } else if (all.size() == 1) {
                entity = all.get(0);
            }
            if (entity == null) {
                if (entityId != null && !entityId.isEmpty()) {
                    throw new SamlError("metadata", "the metadata aggregate has no identity provider " + entityId);
                }
                throw new SamlError("metadata", "the metadata aggregate holds " + all.size() + " identity providers; name one with idpEntityId");
            }
        } else {
            throw new SamlError("metadata", "the identity provider metadata is not an EntityDescriptor");
        }
        String identifier = Xml.attr(entity, "entityID");
        if (identifier == null || identifier.isEmpty()) throw new SamlError("metadata", "the identity provider metadata has no entityID");
        if (entityId != null && !entityId.isEmpty() && !identifier.equals(entityId)) {
            throw new SamlError("metadata", "the metadata describes " + identifier + ", not " + entityId);
        }
        List<Element> roles = Xml.children(entity, Xml.MD, "IDPSSODescriptor");
        if (roles.isEmpty()) throw new SamlError("metadata", identifier + "'s metadata has no IDPSSODescriptor");
        Element role = roles.get(0);
        Map<String, String> ssoUrls = new LinkedHashMap<>();
        for (Element sso : Xml.children(role, Xml.MD, "SingleSignOnService")) {
            String binding = Xml.attr(sso, "Binding");
            String location = Xml.attr(sso, "Location");
            if (location == null || location.isEmpty()) continue;
            if (Xml.BINDING_REDIRECT.equals(binding) && !ssoUrls.containsKey("redirect")) ssoUrls.put("redirect", location);
            if (Xml.BINDING_POST.equals(binding) && !ssoUrls.containsKey("post")) ssoUrls.put("post", location);
        }
        Map<Integer, String> services = new LinkedHashMap<>();
        for (Element ars : Xml.children(role, Xml.MD, "ArtifactResolutionService")) {
            String location = Xml.attr(ars, "Location");
            if (Xml.BINDING_SOAP.equals(Xml.attr(ars, "Binding")) && location != null && !location.isEmpty()) {
                services.put(Integer.parseInt(orZero(Xml.attr(ars, "index"))), location);
            }
        }
        List<X509Certificate> signing = certificatesOf(role, "signing");
        if (signing.isEmpty()) throw new SamlError("metadata", identifier + "'s metadata names no signing certificate");
        if (!ssoUrls.containsKey("redirect") && !ssoUrls.containsKey("post")) {
            throw new SamlError("metadata", identifier + "'s metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService");
        }
        return new IdpMetadata(identifier, ssoUrls, services, signing, "true".equals(Xml.attr(role, "WantAuthnRequestsSigned")));
    }

    public static String writeSpMetadata(String entityId, String acsUrl, X509Certificate certificate, boolean wantAssertionsSigned, String nameIdFormat) {
        String cert = Xml.pemBody(Keys.certificatePem(certificate));
        String keyInfo = "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + cert + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>";
        StringBuilder methods = new StringBuilder();
        for (String method : ENCRYPTION_METHODS) methods.append("\n      <md:EncryptionMethod Algorithm=\"").append(method).append("\"/>");
        String signing = "    <md:KeyDescriptor use=\"signing\">\n      " + keyInfo + "\n    </md:KeyDescriptor>";
        String encryption = "    <md:KeyDescriptor use=\"encryption\">\n      " + keyInfo + methods + "\n    </md:KeyDescriptor>";
        String acs = Xml.escape(acsUrl);
        String nameId = nameIdFormat == null || nameIdFormat.isEmpty() ? "" : "\n    <md:NameIDFormat>" + Xml.escape(nameIdFormat) + "</md:NameIDFormat>";
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<md:EntityDescriptor xmlns:md=\"" + Xml.MD + "\" xmlns:ds=\"" + Xml.DS + "\" entityID=\"" + Xml.escape(entityId) + "\">\n"
            + "  <md:SPSSODescriptor protocolSupportEnumeration=\"" + Xml.SAMLP + "\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\""
            + wantAssertionsSigned + "\">\n" + signing + "\n" + encryption + nameId + "\n"
            + "    <md:AssertionConsumerService Binding=\"" + Xml.BINDING_POST + "\" Location=\"" + acs + "\" index=\"0\" isDefault=\"true\"/>\n"
            + "    <md:AssertionConsumerService Binding=\"" + Xml.BINDING_REDIRECT + "\" Location=\"" + acs + "\" index=\"1\"/>\n"
            + "    <md:AssertionConsumerService Binding=\"" + Xml.BINDING_ARTIFACT + "\" Location=\"" + acs + "\" index=\"2\"/>\n"
            + "  </md:SPSSODescriptor>\n</md:EntityDescriptor>\n";
    }

    private static List<X509Certificate> certificatesOf(Element role, String use) {
        List<X509Certificate> out = new ArrayList<>();
        for (Element descriptor : Xml.children(role, Xml.MD, "KeyDescriptor")) {
            String declared = Xml.attr(descriptor, "use");
            if (declared != null && !declared.isEmpty() && !declared.equals(use)) continue;
            for (Element data : Xml.descendants(descriptor, Xml.DS, "X509Data")) {
                List<Element> first = Xml.children(data, Xml.DS, "X509Certificate");
                if (first.isEmpty()) continue;
                try {
                    out.add(Keys.loadCertificate(Xml.toPem(Xml.text(first.get(0)))));
                } catch (Exception err) {
                    throw new SamlError("metadata", "a " + use + " certificate in the identity provider's metadata cannot be read", err);
                }
            }
        }
        return out;
    }

    private static String orZero(String value) {
        return value == null || value.isEmpty() ? "0" : value;
    }
}
