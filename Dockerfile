# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM maven:3.9.6-eclipse-temurin-17 AS test
# TrustChainTest runs the install script's trust-chain code: python3, and the
# openssl CLI it reads certificate names with.
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Both modules: library/ (the published library) and demo/ (the demo, and
# TrustChainTest, which runs scripts/ against demo/saml.json).
COPY pom.xml .
COPY library library
COPY demo/pom.xml demo/pom.xml
COPY demo/src demo/src
COPY scripts scripts
COPY demo/saml.json demo/saml.json
RUN mvn -B test

FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
COPY library library
COPY demo/pom.xml demo/pom.xml
COPY demo/src demo/src
# The demo module copies its runtime dependencies, the library among them, to demo/target/dependency.
RUN mvn -B -DskipTests package
FROM eclipse-temurin:17-jre
WORKDIR /app
# The demo's jar under the name the image has always run, and beside it every
# runtime dependency, the library jar among them (com.iyasec.saml.Cli is there).
COPY --from=build /src/demo/target/saml2-sp-demo-0.1.0.jar /app/saml2-sp.jar
COPY --from=build /src/demo/target/dependency /app/dependency
# The demo, and with it idpCa's file: demo/generated/idp-ca.pem, the iya-sts
# listener CA trust chain scripts/configure_iya_sts.py saved. The image trusts
# that iya-sts with no bind mount and no fetch. Rebuild after running the
# install script against a different iya-sts.
# .dockerignore admits that one file from demo/generated (never the SP's key,
# certificate or either metadata document). A COPY of the demo DIRECTORY
# succeeds with or without it, so a fresh clone and CI still build; naming the
# file, or a glob that matches nothing, fails the build in both builders. It
# comes after the compile, so a new chain does not rebuild the jar.
COPY demo demo
COPY scripts scripts
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/${PORT} && printf "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" >&3 && grep -q "^ok$" <&3'
CMD ["java", "-cp", "saml2-sp.jar:dependency/*", "com.iyasec.saml.demo.Demo"]
