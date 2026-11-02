# saml2-sp

Server-side SAML 2.0 service provider for Java. It sends a signed `AuthnRequest` on HTTP-Redirect or HTTP-POST, accepts a `Response` on HTTP-POST, HTTP-Redirect, or HTTP-Artifact, verifies XML signatures, decrypts encrypted assertions, and can poll a Shared Signals transmitter for CAEP and RISC events.

Version 0.1.0. License: MIT. `develop` and `main` are one commit. A pull request merged into `main` publishes the library (`library/` only; the demo never) to Maven Central after the test workflow succeeds on that commit. A direct push does not. `publish.yml` runs `mvn -Prelease -f library/pom.xml deploy` in the Maven container: the `release` profile adds the sources and javadoc jars, a GPG signature on every file, and the Central publishing plugin, which uploads, publishes and waits until the release is live. Maven Central has no trusted publishing, so the job uses four repository secrets: `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` (a Central Portal user token) and `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` (the release signing key, whose public half is on a public key server). A release on Central is permanent: a version already there is skipped, and the next release is a new version in `VERSION` and the three poms. `-Dcentral.skipPublishing=true` builds and signs everything and uploads nothing.

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

The suite runs in a container. The tests sign, encrypt, and decrypt with the JDK and Apache Santuario exclusive canonicalization. Security Event Token checks use Nimbus JOSE only for the JWS. They include a stub identity provider and a stub transmitter. The stub tests do not start iya-sts. Java 17.

The suite includes `TrustChainTest`, which runs the install script's trust-chain code (Python and the openssl CLI, installed in the `test` stage) against an HTTPS stub on a four-certificate chain, and checks the library trusts the stub through the file it wrote, trusts a reissued leaf from the same CA, and refuses a forged leaf followed by the real CA certificates and the right chain under the wrong host name.

`python3 scripts/live_iya_sts.py` is the live half. It starts the latest main branch of iya-sts in memory mode with persistence and clustering off when `IYA_STS_URL` is unset (or from `IYA_STS_IMAGE`), copies the checkout to a scratch build context without `demo/generated`, builds the demo image, runs the install script with host `python3 scripts/configure_iya_sts.py` (its Java CLI runs in that image; it writes the key pair, the metadata and `idpCa`'s chain), builds the image again so it carries that chain, checks the image holds the chain and no key, and runs the demo with only `sp.key`, `sp.crt` and `idp-metadata.xml` mounted. It then signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It never binds 3000, 8081 or 18481-18495; its defaults are 18555 (`LIVE_STS_PORT`) and 18655 (`LIVE_DEMO_PORT`). Secrets go to docker as `-e NAME` only, and each sign-in request is logged by a fixed label rather than its URL. The nightly workflow runs the unit suite and this script once every 24 hours. Push CI stays the unit suite.

## Layout

- `library/` the library, `com.iyasec:saml2-sp`, nothing else in its jar: `library/src/main/java/com/iyasec/saml/` (`ServiceProvider`, metadata, bindings, signatures, encryption, the replay cache, `ssf/`)
- `library/src/test/java/com/iyasec/saml/` JUnit 5; `library/src/test-fixtures` the stub identity provider, shared with the demo's tests
- `demo/` the demo module, never published: `demo/src/main/java/com/iyasec/saml/demo/Demo.java`
- `scripts/configure_iya_sts.py` registers that demo with iya-sts and writes `idpCa`
- `scripts/trust_chain.py` fetches and saves the iya-sts listener CA trust chain
- `scripts/live_iya_sts.py` signs the demo in to iya-sts and checks `GET /live-status`
- `Dockerfile` and `docker-compose.yml` run the demo (`network_mode: host`, `PORT` defaults to 3000)
- `.github/workflows/nightly.yml` runs the unit suite and the live script once every 24 hours

## Demo

```bash
docker compose up --build
```

`PORT` defaults to 3000. `GET /healthz` returns `200` and the body `ok` even when the identity provider metadata is not on disk yet. The home page offers sign-in. `/login` answers a signed AuthnRequest (redirect, or a POST form). `/saml/acs` is the assertion consumer. `/saml/metadata` is this service provider's metadata. `GET /live-status` does not need an account id. It is JSON: `signedIn` (true when any local account session exists), `subject`, the receiver state, and the Shared Signals events this process has accepted (`type` and `jti` only). No tokens. If the assertion SessionIndex is not the CAEP session id, the event handler ends this demo's one session and says so. `session-revoked` leaves `signedIn` false. A loopback `entityId` and assertion consumer URL follow `PORT`. Any other host stays as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path; the default `http://localhost:3000` is not treated as an explicit public URL. The live script never binds port 3000 or 8081.

`demo/saml.json` points at `file:` paths under `demo/generated/` and does not contain a key. Generate the key pair and, against a running iya-sts, register the application with:

```bash
python3 scripts/configure_iya_sts.py
```

The container's `PORT` wins over the shell's `PORT` when that script chooses the entityID and assertion consumer URL. A password it generates for the test user goes to `demo/generated/<user>.password` (mode 0600), never to the output.

## The iya-sts trust chain (`idpCa`)

`idpCa` (demo default `file:generated/idp-ca.pem`, relative to `demo/`) is the iya-sts TLS listener CA trust chain the library trusts for the metadata fetch, artifact resolution and Shared Signals. `scripts/configure_iya_sts.py`, the install script, writes it on every run: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that is missing (`scripts/trust_chain.py`). It prints the path, the anchor's subject and its SHA-256; compare the anchor with the Root CA on iya-sts's PKI page. The library makes every certificate in the file a PKIX trust anchor, so a reissued listener certificate from the same CA is trusted; a certificate that merely appears in the presented chain proves nothing, and the host name is checked against the leaf's subject alternative names.

The demo image build copies that file in (`COPY demo demo`, after the compile; `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated`), so a demo image built after the install script trusts that iya-sts with no mount and no fetch. Run the install script before you build the image, and rebuild the image after running it against a different iya-sts. A build with no chain file (a fresh clone, CI) still succeeds. The SP's key, certificate and both metadata documents never enter the image: `docker-compose.yml` mounts `demo/generated` at run time. The shipped demo leaves `signals` unset, so the receiver stays on when `ssf.transmitter` is set.
