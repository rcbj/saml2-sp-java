# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
COPY src src
RUN mvn -B -DskipTests package
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /src/target/saml2-sp-0.1.0.jar /app/saml2-sp.jar
COPY --from=build /src/target/dependency /app/dependency
COPY demo demo
COPY scripts scripts
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/${PORT} && printf "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" >&3 && grep -q "^ok$" <&3'
CMD ["java", "-cp", "saml2-sp.jar:dependency/*", "com.iyasec.saml.demo.Demo"]
