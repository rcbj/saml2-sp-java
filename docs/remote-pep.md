# Using the iya-sts Remote PEP

This library can ask iya-sts's authorization policy whether a signed-in person (a validated `SamlLogin`) may do something to a resource in your application, through an embedded **Remote PEP** (Policy Enforcement Point). The PEP itself is [`com.iyasec:iya-pep`](https://github.com/rcbj/iya-pep-java) 0.1.0. This library builds it from your configuration (`com.iyasec.saml.pep.SamlPep`), turns a SAML 2.0 sign-in into the PEP's subject, and hands it policy-change events from its Shared Signals stream. The design is [iya-sts #1206](https://github.com/rcbj/iya-sts/issues/1206).

The PEP never permits by default. A decision is a Permit, a Deny or Unavailable, and Unavailable (no policy held yet, iya-sts unreachable, or a failure while deciding, which the PEP catches) must be treated as a refusal. `decision.httpStatus()` is 200 for a Permit and 403 for a Deny and for Unavailable alike, never a 5xx a client might retry into a different answer. Whether the person is signed in at all (401) is your application's question, asked before the PEP's.

`decide` does not throw. A failure is an Unavailable decision.

## Choosing a mode

| | `central` | `local` |
|---|---|---|
| Who decides | iya-sts, per request (`POST /access/v1/evaluation`) | this process, with the PEP's own XACML engine |
| Dependency | `com.iyasec:iya-pep` (always on the classpath; there is no feature flag) | the same jar. `local` is the default mode |
| Latency | one HTTPS round trip per decision | none after the first pull |
| When iya-sts is down | every decision is Unavailable, and the Permit cache (if on) is emptied | decisions continue with the policies held |
| Policy changes | at once | on the `pep-policies-changed` event, or the next poll |
| Decision records | written by iya-sts | sent by the PEP to iya-sts's audit log |

Pick `central` when decisions are infrequent or must reflect a change immediately, and `local` when decisions are on a hot path or must survive a short outage. Both modes give the same answer for the same request: `local` maps the request through the realm's catalogue exactly as iya-sts does.

## Before you start: set up iya-sts

You need an iya-sts release with embedded-PEP support (iya-sts #2026, #2027 and #2028). The steps below use the management API; `$API` is `https://<host>/realm/<realm>/admin-api` (or `https://<host>/admin-api` for the default realm) and `$TOKEN` a token for it with write access. Every step has a console equivalent, named after it. `scripts/configure_iya_sts.py --pep` does steps 2 to 6 for the demo.

```bash
api() { curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "$2" "$API/$1"; }
```

### 1. Register the application

Register the service provider from its metadata (`/admin-api/applications/create`, or `/admin-api/saml2/upload-metadata` when it already exists). The install script does this. The application's identifier is this library's `entityId`, which is the PEP's `application` unless you set one.

### 2. Create the PEP's service account

A directory account with no password, owned by `admin-write`, in the group `remote-peps`. The demo's account is `pep-saml-demo` (`--pep-name`).

### 3. Make the PEP's key, certify it and bind the PEP

An EC P-256 key the PEP alone holds, mode 0600. Certify it from its own certificate request and bind it to the application:

```bash
api xacml/issue-pep-credential '{"name":"pep-orders","csr":"<PEM>","application":"<entityId>"}'
```

With the key and the account both kept, `xacml/set-pep-application` binds the account again.

### 4. Declare the claims your policy reads

The realm's AuthZEN catalogue has one row per claim. Subject claims without a row are dropped, not refused. Resource, action and context members without a row are refused, so the decision is a Deny. The demo's install script writes `subject.acr` → `urn:example:acr`, the row every sibling demo shares, and relies on `urn:sts:xacml:attribute:attr1` for the directory attribute `attr1`.

### 5. Write the policy

The demo writes an ALFA policy onto the application's own fine-grained authorization policy and enforces that policy. It does not call `xacml/set-root`. A policy under another PolicyId is left alone. The script's PolicyId is `urn:saml-sp-demo:samlspdemo:orders`.

`read` on an `order` is permitted when the sign-in carried an AuthnContextClassRef. `read` on `attribute-protected` is permitted when `attr1` is `abc123`. Anything else, including `write` on an order, is denied.

### 6. (`local` with signals) let the event through

If the application's entry restricts its Shared Signals streams with `ssfAllowedEvents`, add `urn:iya:sts:secevent:event-type:pep-policies-changed` to it. Otherwise the PEP doesn't hear of a change until its fallback poll. The install script adds the event only when the application already restricts events.

## Build

Depend on `com.iyasec:iya-pep:0.1.0` (this library's `library/pom.xml` already does). Until that artifact is on Maven Central, the image clones `https://github.com/rcbj/iya-pep-java.git` branch `develop` and installs it before `mvn test` or `mvn package`. A failed clone is not retried. Do not run Maven on the host.

There is no Cargo-style feature. A `pep` section is ignored only when it is absent. A section that names no `mode` is `local`.

## Configure

Add a `pep` section to `saml.json`. The PEP is off unless it is present.

```json
"pep": {
  "name": "pep-orders",
  "mode": "local",
  "assertionKey": "pep-key.pem"
}
```

| Member | Default here | What it is |
|---|---|---|
| `name` | required | The PEP's service account (step 2). |
| `mode` | `local` | `local` (the PEP pulls its application's policies and decides in process) or `central` (it asks iya-sts for every decision). |
| `assertionKey` | required | The PEP's private key in PEM: a path. A relative one is read from the configuration file's directory, like `privateKey`. The PEP reads the file itself, and again when it changes. |
| `pdpUrl` | the identity provider's entityID. iya-sts's SAML entityID is the realm's issuer, so this is the service's URL with the realm prefix | iya-sts, with `/realm/<id>` for a realm. When that entityID is not an http(s) URL, name the service here. |
| `application` | `entityId` | The application the PEP is bound to (step 3). |
| `clientId` | `sts-remote-pep` | The client the PEP's assertion is presented through. |
| `signals` | on when this library's receiver runs (an `ssf` object, and `signals` not `false`) | Whether a signal stream hands over policy-change events. Without one, `local` polls at `pollIntervalMs`. |
| `pollIntervalMs` | 15000 | `local` without a signal stream. |
| `fallbackPollMs` | 300000 | `local` with one, in case an event is lost. |
| `heartbeatIntervalMs` | 30000 | How often the PEP reports to iya-sts. |
| `permitCacheMs` | 0 (off) | `central` only: reuse a Permit for this long, at most 60000. A policy-change event clears it, and so does a failed evaluation or a failed heartbeat. |
| `supportedObligations` | `[]` | The obligation types your application discharges. |
| `decisionRecords` | `true` | `local`: send each decision to iya-sts's audit log. |
| `tlsCa` | `idpCa` (the PEM) | PEM trust anchors for iya-sts's TLS. |
| `timeoutMs` | 10000 | Per request to iya-sts. |

An unknown member is refused. `ServiceProvider.create` and `fromFile` start the PEP after the identity provider's metadata is read (the `pdpUrl` default needs its entityID). `start` registers and, in `local` mode, pulls once. An unreachable service is retried on the PEP's own thread. Decisions are Unavailable until then.

`ssf.clientCertificate` and `ssf.clientKey` are the receiver's own TLS client identity: both or neither (PEM, a path relative to the configuration, or a placeholder). They must parse as a certificate and a PKCS#8 key. The demo presents that pair, and falls back to the SP key pair.

## Decide

```java
ServiceProvider sp = ServiceProvider.fromFile("saml.json");
Access access = Access.of("read", "order", orderId);
Decision decision = sp.decideSession(receiver.sessionIndex(), localId, login, access);
int status = decision.httpStatus(); // 200 for a Permit, 403 for anything else
if (decision.isPermit()) {
    serve(decision.obligations());
} else if (decision.kind() == Decision.Kind.DENY) {
    forbidden(status, decision.why());
} else {
    forbidden(status, decision.why()); // Unavailable: fail closed
}
// Without a receiver: sp.decide(login, access)
```

`httpStatus()` is the rule rather than a convention. The demo's two protected pages take their status from it.

`Access.of(action, resourceType, resourceId)` carries the AuthZEN action and resource. `actionProperties`, `resourceProperties` and `context` are public maps of JSON values, each declared in the catalogue (step 4). The PEP sets `context.application` to the bound application.

**The subject** comes from the sign-in, never from a request header (`SamlPep.subjectOf`):

- **id:** `SamlLogin.username()`: the first non-empty value of `username`, `preferred_username`, `urn:oid:0.9.2342.19200300.100.1.1`, `uid` and `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`, else the NameID. iya-sts's PIP resolves a username, a DN or a certificate subject. A transient NameID names nobody it can resolve.
- **properties:** the attributes (by Name, and by FriendlyName when that is not also a Name): one value as a string, several as an array. `AuthnContextClassRef` is `acr`. `amr`, or the AD FS claim `http://schemas.microsoft.com/claims/authnmethodsreferences`, is `amr`. `AuthnInstant` is `auth_time` in epoch seconds.

Only the properties the catalogue declares are sent.

**Ended sessions.** `decideSession` checks the session index first (`MemorySessionIndex.contains`). A session that is not tracked, or whose `expiresAt` is in the past, is a Deny (`no signed-in session`). iya-sts is not asked. Sign-out calls `untrack`. An ending CAEP or RISC event calls the same removal (`forget`).

**Without a `pep` section**, every decision is Unavailable (`no pep section is configured`). `httpStatus()` is still 403.

### Obligations

A Permit can carry obligations, which your application must carry out before it grants the access. The PEP only hands you obligations of types you list in `supportedObligations`. A Permit carrying any other obligation is turned into a Deny. Advice can be ignored.

```json
"pep": { "name": "pep-orders", "assertionKey": "pep-key.pem", "supportedObligations": ["step-up"] }
```

## Receive policy-change events

In `local` mode, and in `central` mode with a Permit cache (`SamlPep.wantsEvents`), the PEP wants to hear when the policies change. Give the receiver the PEP:

```java
SignalsReceiver receiver = new SignalsReceiver(transmitterUrl, this::endSessions)
    .tls(tls)
    .sessionIndex(sessions)
    .pep(sp.pep());
receiver.start();
```

`start` checks the TLS client key before any network call. It then asks the stream for `Pep.POLICIES_CHANGED_EVENT` (`urn:iya:sts:secevent:event-type:pep-policies-changed`), verifies each SET like every other one, and hands the event body to `onPolicyEvent`. A stream that already exists is updated with PATCH to ask for the missing types. If the transmitter refuses, the receiver still starts, the refusal goes to the receiver's log at error, and the PEP is told the event is excluded. The event is only a hint: the PEP pulls with its own credential.

The receiver tells the PEP how its stream is doing: `requested` or `excluded` at start and after each good poll, and `down` after a failed poll and on `stop()`.

It also tells the transmitter whose events it wants. Each `track` queues Add Subject for the person's `iss_sub` (the subject attribute) and `email`, with `verified: true`. `untrack`, and an event that ends the session, queue Remove Subject for each identifier no other local session holds. Both go out on the poll thread, once, and are never retried. A 403 is a warning (the transmitter may not know an active session yet). Other failures are errors. The latest is `subjectError()`. At most 1000 calls are queued. `"ssf": {"addSubjects": false}` turns this off. A transmitter without `add_subject_endpoint` and `remove_subject_endpoint` gets nothing.

The application's opaque subject `{format: opaque, id: <application>}` is added at start, ahead of the people, and is never removed. `pep-policies-changed` is about that application. Once people are added, a stream that names subjects would otherwise stop carrying it.

## Operate it

- **Health.** `pep.status()` reports whether the PEP is registered and running, whether it holds a policy, its decision counters and its current problems. `SamlPep.statusMap` turns that into a map. It holds no secret. The demo puts it on `GET /live-status` under `pep` when the file has a `pep` section, and on `GET /pep-status` (401 without a sign-in).
- **In the console.** The PEP appears under **Protocols → XACML → Remote PEPs**. The application's page lists the PEPs bound to it.
- **Rotating the key.** Generate a new key, certify it with `issue-pep-credential`, and replace the file. The PEP reads the file again when it changes.
- **Audit.** In `local` mode each decision becomes an audit row in iya-sts. In `central` mode iya-sts records its own.

## Credentials

The README's [Credentials](../README.md#credentials) section covers every credential the demo uses. This section covers the embedded PEP's.

### The application's own credentials

The SAML key pair (`privateKey` / `certificate`) signs AuthnRequests and decrypts assertions. iya-sts learns it from the SP metadata. The Shared Signals receiver presents its own TLS client certificate, which the realm issues the application (`ssf.clientCertificate` / `ssf.clientKey`), and falls back to the SAML key pair without one. The PEP uses neither.

### The embedded PEP's credentials

- **The service account** (step 2): a directory account with no password, in `remote-peps`. It is the PEP's identity. The key is bound to it, and through it to one application (`application`, by default this SP's `entityId`).
- **The key** (`assertionKey`, step 3): an EC P-256 key the PEP alone holds. Make it yourself and keep it 0600. iya-sts certifies it from its CSR (`issue-pep-credential`). With an unchanged key, `set-pep-application` binds the account again.
- **What it authenticates:** every call the PEP makes. It signs an RFC 7523 self-assertion for a DPoP-bound (RFC 9449) access token, and signs each DPoP proof. No token, key or proof is logged.
- **Not the application's keys.** `SamlPep.build` refuses a configuration whose `assertionKey` has the JWK thumbprint of `privateKey` (signing, decryption, and the receiver's TLS key when there is no `ssf.clientKey`) or of `ssf.clientKey`. `SignalsReceiver.start` refuses a PEP whose key is the TLS client key the receiver will present. The error names both keys.
- **Rotation:** replace the key file and certify the new key. With the demo, delete `demo/generated/pep-key.pem` and run the install script again.

### Install-time only

The steps above are management calls. Their token comes from `ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET` (the environment, never stored). Defining the realm's custom attribute `attr1` uses a token minted with `admin:read admin:security` for that call alone. The PEP never sees those secrets. The one-time password that opens the issued SSF client key is not printed and is not stored.

### Trust material

`tlsCa` (default the `idpCa` PEM, iya-sts's TLS listener chain) verifies iya-sts for the PEP's calls. A `pep-policies-changed` event reaches the PEP only through the receiver, which verified the SET against the transmitter's JWKS. The PEP then pulls the policies with its own token.

### Development and product iya-sts

The PEP's credential is the same in both modes: a certified key and a DPoP-bound token. The receiver's realm-issued TLS client certificate is checked the same way in both.

## Troubleshooting

| What you see | Likely cause |
|---|---|
| Every decision Unavailable, `status().registered` false, a problem mentioning 403 | The PEP's entry has no binding, or is bound to another application (iya-sts `STS-XACML-0338`, `0339`). Repeat step 3 with the right `application`. |
| Unavailable and a problem naming the token endpoint (`invalid_grant`) | The key isn't certified for this account, or the account isn't in `remote-peps` (steps 2 and 3). |
| Unavailable with "no policy is held yet" (`local`) | The first pull hasn't succeeded. A 403 on the policy pull (`STS-XACML-0343`) means the PEP isn't registered as an embedded `local` PEP bound to that application. |
| A registration refused with 400 (`STS-XACML-0340`) | The iya-sts release doesn't support this PEP's protocol version. Upgrade iya-sts or this library. |
| Deny saying the evaluation was refused | A resource, action or context property you sent has no catalogue row (step 4). Subject claims without a row are dropped, not refused. |
| Deny although the policy should permit | The policy reads a claim that has no catalogue row, so it never arrives (step 4). Or a Permit carried an obligation type missing from `supportedObligations`. |
| Policy changes take minutes to apply (`local`) | The stream doesn't carry the event: check `ssfAllowedEvents` (step 6) and the receiver's log for a refused stream update. |
| The configuration is refused for the assertion key | It is `privateKey`, or `ssf.clientKey`, or the receiver's TLS client key. The PEP needs a key of its own. |
| `pep.pdpUrl` and the identity provider's entityID | That entityID is not an http(s) URL. Name the service in `pep.pdpUrl`. |

## Testing central against local

The Rust library compares `central` and `local` with an AuthZEN case table and `scripts/live_authzen.py`. This Java library does not carry that table or that script. `docker build --target test .` runs the SAML wiring tests (subject id, section defaults, the two key refusals, and a Deny for an untracked or expired session). It does not start a PEP against a PDP.

## The demo

With a `pep` section, the demo protects `GET /attribute-protected` (`Access.of("read", "attribute-protected", "attr1")`) and `/orders/<id>` (`read` on GET, `write` on any other method, type `order`, id the path segment). No sign-in is 401. The status after that is `decision.httpStatus()`: 200 on a Permit, 403 on a Deny and on Unavailable. When the service provider will not load, the page is 403 as well. The first non-expired account in the `aset` cookie is the subject. `decideSession` uses the index the receiver shares, so a session that was signed out or ended by an event is a Deny even if a cookie still names it.

One command sets the demo up: `python3 scripts/configure_iya_sts.py --pep local` (or a bare `--pep`) or `--pep central` (`--pep-name`, default `pep-saml-demo`). After registering the service provider it does steps 2 to 6, gives the test user `attr1=abc123`, and writes the `pep` section (`name`, `mode`, `assertionKey: generated/pep-key.pem`), keeping other members. The Shared Signals receiver's TLS client certificate is the one the realm issues (`generated/ssf-client.key` mode 0600 and `generated/ssf-client.crt`). The SP certificate is not added to the process-wide truststore. An anchor an earlier run added is removed. `--dry-run` lists every call and prints no secret.

```sh
docker compose build
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" -e ADMIN_API_CLIENT_SECRET -e IYA_STS_URL \
  saml2-sp-java-demo python3 scripts/configure_iya_sts.py --pep local
docker compose up --build
```

Run it again against the same iya-sts to switch the mode: the account, the key and an administrator's policy are kept, and the PEP is bound again. `GET /live-status` includes the PEP's status under `pep`. The image copies `demo/saml.json` in when it is built, so rebuild after the script writes the section. Compose mounts `demo/generated`, which holds the PEP's key and the receiver's key. Neither enters the image (`.dockerignore` admits only `idp-ca.pem`).

The signed-in home page links the two protected pages. `GET /pep-status` returns `{pep: ...}` as JSON and is 401 without a sign-in. This demo does not have the Rust demo's three tabs, collapsible panes, or `pep.js`. It does not have a Playwright UI test (`live_ui.py`) or a live script that flips the policy and checks a denied user. Those remain in the Rust library.

## See also

- [`iya-pep`'s README](https://github.com/rcbj/iya-pep-java#readme): the package's own API and every configuration member.
- iya-sts's [Remote PEP page](https://rcbj.github.io/iya-sts/v1.2.0/remote-pep.html): the service's side of the binding, registration and the scoped pull.
- iya-sts's [CAEP events page](https://rcbj.github.io/iya-sts/v1.2.0/caep-events.html): the `pep-policies-changed` event.
