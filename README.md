# saml2-sp

Server-side SAML 2.0 service provider for Java. It sends a signed `AuthnRequest` on HTTP-Redirect or HTTP-POST, accepts a `Response` on HTTP-POST, HTTP-Redirect, or HTTP-Artifact, verifies XML signatures, decrypts encrypted assertions, and can poll a Shared Signals transmitter for CAEP and RISC events.

Version 0.1.0. License: MIT. `develop` and `main` are one commit. Publishing to Maven Central is not set up.

## Usage

```java
ServiceProvider sp = ServiceProvider.fromFile("saml.json");
LoginRequest request = sp.login(options); // options.relayState = "/home"
SamlLogin who = sp.acs(method, url, body, request.id);
```

`saml.json` uses the same keys as the Node service provider: `entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, and the optional `requestBinding`, `responseBinding`, `idpCa`, `idpEntityId`, `nameIdFormat`, `clockSkewSeconds`, `wantAssertionsSigned`, `wantAssertionsEncrypted`, `allowUnsolicited`, and `signals`. A value may be PEM text, a file path, or an `env:` / `file:` placeholder. `signals` omitted or `true` leaves the Shared Signals receiver available. `false` turns it off and does not require transmitter metadata. Any other value is a configuration error: `signals must be true or false`. The resolved configuration omits `signals` when the receiver is on and includes `signals: false` when it is off. SAML does not send OAuth scopes, so the flag does not change the `AuthnRequest`.

Methods match the TypeScript names: `fromFile`, `login`, `acs`, `postFormHtml`. Group `com.iyasec`, artifact `saml2-sp`, packages under `com.iyasec.saml`.

```bash
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  saml2-sp-java-demo \
  java -cp 'saml2-sp.jar:dependency/*' \
  com.iyasec.saml.Cli generate-keys --config demo/saml.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  saml2-sp-java-demo \
  java -cp 'saml2-sp.jar:dependency/*' \
  com.iyasec.saml.Cli metadata --config demo/saml.json
```

`postFormHtml` builds the HTTP-POST form. HTTP-Redirect signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Success is `urn:oasis:names:tc:SAML:2.0:status:Success`. `generate-keys` writes a self-signed RSA certificate.

## Shared Signals

```java
SignalsReceiver receiver = new SignalsReceiver("https://idp.example", this::end);
receiver.track(localId, login);
receiver.start();
```

The receiver lives in `com.iyasec.saml.ssf`. It discovers the transmitter, keeps one poll stream (`urn:ietf:rfc:8936`), and verifies each Security Event Token against the published JWKS. By default a session ends on `session-revoked`, `account-disabled`, `account-purged`, `credential-compromise`, and `sessions-revoked`.

## Errors

A caught exception is written to `java.lang.System.Logger` with its stack. The JDK sends that logger to `java.util.logging` unless the application installs a `System.LoggerFinder`. Where this library already threw `SamlError`, it still throws `SamlError`, and the caught exception is the cause.

A catch that recovers does not throw. It is still logged. A poll is retried, the next signing key is tried, an HTTP error body is read, sign-out still finishes after a revoke fails, and a Shared Signals handler that throws does not stop acknowledgement of that event. Passing a `SamlError` through is not logged again: the foreign exception was logged where it was caught.

## Tests

```bash
docker build --target test .
```

The suite runs in a container. The tests sign, encrypt, and decrypt with the JDK and Apache Santuario exclusive canonicalization. Security Event Token checks use Nimbus JOSE only for the JWS. They include a stub identity provider and a stub transmitter. They do not need a live iya-sts. Java 17.

## Layout

- `src/main/java/com/iyasec/saml/` the library (`ServiceProvider`, metadata, bindings, signatures, encryption, the replay cache, `ssf/`)
- `src/test/java/com/iyasec/saml/` JUnit 5, including the stub identity provider
- `src/main/java/com/iyasec/saml/demo/Demo.java` the demo
- `scripts/configure_iya_sts.py` registers that demo with iya-sts
- `Dockerfile` and `docker-compose.yml` run the demo (`network_mode: host`, `PORT` defaults to 3000)

## Demo

```bash
docker compose up --build
```

`PORT` defaults to 3000. `GET /healthz` returns `200` and the body `ok` even when the identity provider metadata is not on disk yet. The home page offers sign-in. `/login` answers a signed AuthnRequest (redirect, or a POST form). `/saml/acs` is the assertion consumer. `/saml/metadata` is this service provider's metadata. A loopback `entityId` and assertion consumer URL follow `PORT`. Any other host stays as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path; the default `http://localhost:3000` is not treated as an explicit public URL.

`demo/saml.json` points at `file:` paths under `demo/generated/` and does not contain a key. Generate the key pair and, against a running iya-sts, register the application with:

```bash
python3 scripts/configure_iya_sts.py
```

The container's `PORT` wins over the shell's `PORT` when that script chooses the entityID and assertion consumer URL. The shipped demo leaves `signals` unset, so the receiver stays on when `ssf.transmitter` is set.
