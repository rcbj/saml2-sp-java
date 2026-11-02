// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.saml;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;


/** saml2-sp's command line: a key pair, this service provider's metadata, and a metadata summary. */
public final class Cli {
    static final String USAGE = """
Usage:
  saml2-sp generate-keys --config <saml.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]
  saml2-sp generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]
      A new RSA key and a self-signed certificate, written where the configuration's privateKey and
      certificate point (or to --key and --cert). Refuses to replace existing files without --force.
      The common name defaults to the host of the configuration's entityId.

  saml2-sp metadata --config <saml.json> [--out <file>] [--entity-id <url>] [--acs-url <url>]
      This service provider's SAML metadata, from the configuration and its certificate. Written to
      --out, or to standard output. --entity-id and --acs-url replace the file's values for this run.

  saml2-sp summarize-idp
      Read identity-provider metadata on standard input. Write the entityID, one single sign-on URL,
      and each artifact resolution URL, one per line.""";

    private Cli() {}

    public static void main(String[] args) {
        try {
            run(args);
        } catch (Exit err) {
            if (err.status != 0) {
                System.err.println(err.getMessage());
                System.exit(1);
            }
        } catch (SamlError err) {
            System.err.println(err.getMessage());
            System.exit(1);
        } catch (Exception err) {
            System.err.println(err.getMessage());
            System.exit(1);
        }
    }

    static void run(String[] args) throws Exception {
        if (args.length == 0 || "help".equals(args[0]) || has(args, "--help")) {
            System.out.print(USAGE);
            return;
        }
        String command = args[0];
        Map<String, String> options = options(args);
        if ("generate-keys".equals(command)) {
            generate(options);
            return;
        }
        if ("metadata".equals(command)) {
            metadata(options);
            return;
        }
        if ("summarize-idp".equals(command)) {
            summarize(new String(System.in.readAllBytes(), StandardCharsets.UTF_8));
            return;
        }
        throw new Exit("unknown command " + command + "\n\n" + USAGE);
    }

    private static void generate(Map<String, String> options) throws Exception {
        Paths paths = keyPaths(options);
        boolean force = options.containsKey("force");
        if (!force && (Files.exists(paths.key) || Files.exists(paths.cert))) {
            Path which = Files.exists(paths.key) ? paths.key : paths.cert;
            throw new Exit(which + " already exists; pass --force to replace the key pair.\n"
                + "Replacing it means giving the identity provider the new metadata before the next sign-in.");
        }
        int days = options.containsKey("days") ? Integer.parseInt(options.get("days")) : 1095;
        int bits = options.containsKey("bits") ? Integer.parseInt(options.get("bits")) : 3072;
        if (options.containsKey("days") && days <= 0) throw new Exit("--days must be a positive whole number");
        if (options.containsKey("bits") && bits != 2048 && bits != 3072 && bits != 4096) {
            throw new Exit("--bits must be 2048, 3072 or 4096");
        }
        Keys.KeyPair pair = Keys.createSelfSigned(paths.commonName, days, bits);
        if (paths.key.getParent() != null) Files.createDirectories(paths.key.getParent());
        Files.writeString(paths.key, pair.privateKeyPem());
        Files.writeString(paths.cert, pair.certificatePem());
        try {
            Files.setPosixFilePermissions(paths.key, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            Files.setPosixFilePermissions(paths.cert, EnumSet.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ));
        } catch (UnsupportedOperationException ignored) {
            // Windows has no POSIX modes. The files are still the key pair.
        }
        System.out.println("Wrote the private key  " + paths.key + " (mode 600)");
        System.out.println("Wrote the certificate  " + paths.cert);
        System.out.println("  subject   CN=" + paths.commonName);
        System.out.println("  valid to  " + pair.validTo());
        System.out.println("  sha256    " + pair.fingerprint256());
    }

    private static void metadata(Map<String, String> options) throws Exception {
        String configPath = options.get("config");
        if (configPath == null) throw new Exit("metadata needs --config\n\n" + USAGE);
        Object parsed = Json.parse(Files.readString(Path.of(configPath)));
        if (!(parsed instanceof Map<?, ?> rawMap)) throw new Exit("the configuration must be an object");
        Map<String, Object> raw = new LinkedHashMap<>();
        rawMap.forEach((key, value) -> raw.put(String.valueOf(key), value));
        raw.remove("idpCa");
        if (options.get("entity-id") != null) raw.put("entityId", options.get("entity-id"));
        if (options.get("acs-url") != null) raw.put("acsUrl", options.get("acs-url"));
        String xml = new ServiceProvider(Config.resolveConfig(new LinkedHashMap<>(raw), Path.of(configPath).toAbsolutePath().getParent().toString()), null, null).metadata();
        String target = options.get("out");
        if (target != null) {
            Path path = Path.of(target).toAbsolutePath();
            if (path.getParent() != null) Files.createDirectories(path.getParent());
            Files.writeString(path, xml);
            System.out.println("Wrote the service provider metadata to " + path);
        } else {
            System.out.print(xml);
        }
    }

    private static void summarize(String xml) {
        Metadata.IdpMetadata meta = Metadata.readIdpMetadata(xml, null);
        String sso = meta.ssoUrls.getOrDefault("redirect", meta.ssoUrls.get("post"));
        System.out.println(meta.entityId);
        System.out.println(sso == null ? "" : sso);
        for (String url : meta.artifactResolutionServices.values()) System.out.println(url);
    }

    private static Paths keyPaths(Map<String, String> options) throws Exception {
        String configPath = options.get("config");
        String key = options.get("key");
        String cert = options.get("cert");
        String commonName = options.get("cn");
        if (configPath != null) {
            Object parsed = Json.parse(Files.readString(Path.of(configPath)));
            if (!(parsed instanceof Map<?, ?> rawMap)) throw new Exit(configPath + " cannot be read as JSON");
            Map<String, Object> raw = new LinkedHashMap<>();
            rawMap.forEach((name, value) -> raw.put(String.valueOf(name), value));
            Path base = Path.of(configPath).toAbsolutePath().getParent();
            key = key == null ? at(raw.get("privateKey"), "privateKey", configPath, base) : key;
            cert = cert == null ? at(raw.get("certificate"), "certificate", configPath, base) : cert;
            if (commonName == null && raw.get("entityId") instanceof String entity) {
                try {
                    String host = java.net.URI.create(entity).getHost();
                    commonName = host == null || host.isEmpty() ? entity : host;
                } catch (Exception err) {
                    commonName = entity;
                }
            }
        }
        if (key == null || cert == null) throw new Exit("generate-keys needs --config, or --key and --cert\n\n" + USAGE);
        return new Paths(Path.of(key).toAbsolutePath(), Path.of(cert).toAbsolutePath(),
            commonName == null || commonName.isEmpty() ? "saml2-sp service provider" : commonName);
    }

    private static String at(Object path, String what, String configPath, Path base) {
        if (!(path instanceof String value) || value.isEmpty() || value.contains("-----BEGIN ") || value.startsWith("env:")) {
            throw new Exit(configPath + "'s " + what + " must be a file path for generate-keys to write to");
        }
        if (value.startsWith("file:")) value = value.substring(5);
        if (value.startsWith("env:")) throw new Exit(configPath + "'s " + what + " must be a file path for generate-keys to write to");
        Path candidate = Path.of(value);
        return (candidate.isAbsolute() ? candidate : base.resolve(candidate)).toAbsolutePath().normalize().toString();
    }

    private static Map<String, String> options(String[] args) {
        Map<String, String> out = new LinkedHashMap<>();
        for (int index = 1; index < args.length; index++) {
            String item = args[index];
            if (!item.startsWith("--")) throw new Exit("unexpected argument " + item + "\n\n" + USAGE);
            String key = item.substring(2);
            if ("force".equals(key) || "help".equals(key)) {
                out.put(key, "true");
                continue;
            }
            if (index + 1 >= args.length || args[index + 1].startsWith("--")) throw new Exit("--" + key + " needs a value\n\n" + USAGE);
            out.put(key, args[++index]);
        }
        return out;
    }

    private static boolean has(String[] args, String flag) {
        for (String arg : args) if (flag.equals(arg)) return true;
        return false;
    }

    private record Paths(Path key, Path cert, String commonName) {}

    static final class Exit extends RuntimeException {
        final int status;
        Exit(String message) { super(message); this.status = 1; }
    }
}
