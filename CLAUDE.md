# saml2-sp

Java service provider for SAML 2.0 Web Browser SSO, plus a Shared Signals poll receiver. Version 0.1.0. MIT. `develop` and `main` are one commit. Publishing is not set up.

## Usage

`ServiceProvider.fromFile("saml.json")`, then `login` and `acs(method, url, body, requestId)`. JSON keys match the Node configuration (`entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, bindings, `signals`, `ssf`). Methods match the TypeScript names (`fromFile`, `login`, `acs`, `postFormHtml`). Group `com.iyasec`, artifact `saml2-sp`, packages under `com.iyasec.saml`.

`signals` omitted or `true` keeps the receiver available and is omitted from the resolved configuration. `false` does not start a receiver and does not require transmitter metadata, and the resolved configuration includes `signals: false`. A non-boolean raises `signals must be true or false`. The flag does not change the AuthnRequest: SAML does not send OAuth scopes.

Request bindings are `redirect` and `post`. Response bindings are `post`, `redirect`, and `artifact`. Artifact resolution is a signed SOAP `ArtifactResolve`. HTTP-Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Success is `urn:oasis:names:tc:SAML:2.0:status:Success`. `com.iyasec.saml.Cli generate-keys` writes a self-signed RSA certificate.

## Tests

```bash
mvn -B test
```

Signatures and decryption are real (JDK ciphers, Apache Santuario exclusive canonicalization). Nimbus JOSE verifies Shared Signals JWS only. The stub identity provider is in `src/test/java/com/iyasec/saml/StubIdp.java`. No live iya-sts. Java 17.

## Layout

`src/main/java/com/iyasec/saml/` library, `ssf/` receiver, `src/test/java/`, `com.iyasec.saml.demo.Demo`, `scripts/configure_iya_sts.py`, `Dockerfile`, `docker-compose.yml`. The image name is `saml2-sp-java-demo`. Compose uses `network_mode: host`, service `saml-demo`, and `ENV PORT=3000` in the image. The health check is `http://127.0.0.1:${PORT}/healthz`.

## Demo

`mvn exec:java`. `GET /healthz` is `200` with body `ok` and does not load the service provider. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, logout of one account or every account, metadata, and per-account Shared Signals events. Loopback entityID and assertion-consumer URLs follow `PORT`. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

## Signals

With an `ssf` block and without `"signals": false`, the demo starts one poll receiver on the service provider's certificate (mutual TLS). The first poll runs on a background thread so a down transmitter does not block a page. `scripts/configure_iya_sts.py` registers the SP metadata, pins AES-256-GCM / RSA-OAEP, turns on multiple accounts, and, unless signals are off, grants `ssf.manage`. The container `PORT` wins over the shell `PORT` at registration.
