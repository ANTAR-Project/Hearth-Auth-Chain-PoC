# HEARTH Auth Chain — Complete Implementation Doc

ANTAR · HEARTH Auth Chain v1.0 · 20 November 2026 · Fabric: .10 only

---

## Scope and constraints applied

| Decision | Value |
|---|---|
| Fabric | .10 only. No .60. |
| Auth-service | Rewritten from scratch. Old code deleted. |
| DBs | Day-0 creation + seeding scripts only. No Flyway migrations from old schema. |
| FKs | No cross-service FKs. Each service owns its DB entirely. |
| DB ownership | `antar_auth` → auth-service. `antar_policy` → policy-registry. Separate DBs, separate roles. |
| policy_rules | `rule_name TEXT NOT NULL` column added (AAA.BBB.CCC format, e.g. `nas.upload.file`). Used for fast lookup and gateway manifest compatibility. |
| Scopes in DB | Strictly bounded to `OWN`, `SHARED`, and `ANY`. `GRANTED` and `ASSIGNED` are dropped completely. |
| Elements section | Ignored except element-registry stub (to exercise ELEMENT domain flag branching). |
| resource_grants | Completely dropped. Table omitted from schema; no grants logic. |
| Boot version | 4.1.1 everywhere. Spring Cloud BOM 2025.1.4. Spring gRPC 1.0.3. |
| JWT library | `nimbus-jose-jwt` (not jjwt). `hearth-auth-common` manages all JWT ops. |
| Gateway starter | `spring-cloud-starter-gateway-server-webflux` (Boot 4.x path). |

---

## Repository layout after implementation

```
Hearth-Auth-Chain-PoC/
├── hearth-auth-common/          ← NEW: shared library (plain jar, no Spring)
│   ├── pom.xml
│   └── src/main/java/com/tamojit/hearth/common/
│       ├── Hearth.java
│       ├── Intent.java
│       ├── BindCalculator.java
│       ├── JwtVerifier.java
│       ├── DiskBackedJwkSource.java
│       ├── ProblemDetails.java
│       └── ScopeEnforcer.java
├── api-gateway/                 ← NEW
├── auth-service/                ← REWRITTEN FROM SCRATCH
├── policy-registry/             ← NEW
├── element-registry/            ← NEW stub
├── nas-orchestrator/            ← CHANGED (PEP #2 filter, /internal/** paths)
├── video-service/               ← CHANGED (use context token + service JWT)
├── encoding-service/            ← CHANGED (service JWT from client_credentials)
├── streaming-service/           ← CHANGED (context token)
├── notification-service/        ← CHANGED (context token at WS handshake)
├── postgres-init/
│   └── 01-provision-databases.sh  ← REWRITTEN (Day-0)
├── proto/
│   ├── auth.proto               ← KEPT (until P7 cutover)
│   └── policy.proto             ← NEW
├── docker-compose.yml           ← REWRITTEN
└── Dockerfile                   ← kept (postgres init image base)
```

---

## Conflicts and resolutions

| Topic | Resolution used here |
|---|---|
| DB ownership & FKs | Services own their respective DBs. `antar_auth` owns users/sessions/service_clients, `antar_policy` owns policy_rules/policy_meta. No cross-service FKs exist anywhere. |
| Scopes | Strictly bounded to `OWN`, `SHARED`, and `ANY`. `GRANTED` and `ASSIGNED` are dropped completely from the database ENUM, entities, and enforcers. |
| Scope semantics | `OWN`: workspace matches username (`resource.id == subject.username`). `SHARED`: resource is within the shared space/root (`namespace == SHARED`). `ANY`: unrestricted within resource type. |
| `resource_grants` | Omitted completely from the database schema and service code. |
| `rule_name` column | Added to `policy_rules`. Format: `{domain}.{resource}.{verb}` e.g. `nas.workspace.list`, `nas.upload.file`, `media.playback.start`, `element.device.control`. Must match the `intent` field in the gateway route manifest. |
| DB naming | auth-service DB: `antar_auth`, role: `antar_auth`. Policy-registry DB: `antar_policy`, role: `antar_policy`. Completely separate. |
| `jwtProcessorCustomizer` | Not used. `JwtVerifier` from `hearth-auth-common` (Nimbus direct) is used in all services. Boot 4 / Spring Security 7 path. |
| Gateway starter | `spring-cloud-starter-gateway-server-webflux`. Properties: `spring.cloud.gateway.server.webflux.*` |

---

## Phase 0: `hearth-auth-common` library

### 0.1 `hearth-auth-common/pom.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
           https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.tamojit</groupId>
  <artifactId>hearth-auth-common</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <properties>
    <java.version>21</java.version>
    <maven.compiler.source>21</maven.compiler.source>
    <maven.compiler.target>21</maven.compiler.target>
    <nimbus.version>9.37.3</nimbus.version>
    <jackson.version>2.17.2</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.nimbusds</groupId>
      <artifactId>nimbus-jose-jwt</artifactId>
      <version>${nimbus.version}</version>
    </dependency>
    <!-- Jackson 2.x — pinned. Boot 4 defaults to Jackson 3; this lib must not use it. -->
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.13</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.11.0</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.13.0</version>
        <configuration><release>21</release></configuration>
      </plugin>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-surefire-plugin</artifactId>
        <version>3.2.5</version>
      </plugin>
    </plugins>
  </build>
</project>
```

### 0.2 Source files

**Package root:** `com.tamojit.hearth.common`

#### `Hearth.java`

```java
package com.tamojit.hearth.common;

public final class Hearth {
    public static final String CTX_HEADER    = "X-Hearth-Context";
    public static final String INTENT_HEADER = "X-Hearth-Intent-Id";
    public static final String TYP_CTX       = "hearth-ctx+jwt";
    public static final String TYP_TICKET    = "hearth-ticket+jwt";
    public static final String ISS_GATEWAY   = "hearth-gateway";
    public static final String ISS_AUTH      = "hearth-auth";
    private Hearth() {}
}
```

#### `Intent.java`

```java
package com.tamojit.hearth.common;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record Intent(
        String intentId,
        String idempotencyKey,
        String name,          // AAA.BBB.CCC, e.g. nas.workspace.list
        String action,        // CREATE | READ | LIST | UPDATE | DELETE | STREAM | MANAGE
        Resource resource,
        List<Resource> relatedResources,
        String namespace,     // OWNED | SHARED
        Map<String, Object> params,
        Subject subject,
        Instant issuedAt,
        Instant expiresAt,
        Decision decision
) {
    public record Resource(String type, String id, String qualifier, Map<String, String> attrs) {}
    public record Subject(String userId, String username, String role, String sessionId) {}
    public record Decision(String effect, String scope) {}  // effect: ALLOW|DENY, scope: OWN|SHARED|ANY

    public Intent withDecision(Decision d) {
        return new Intent(intentId, idempotencyKey, name, action, resource, relatedResources,
                namespace, params, subject, issuedAt, expiresAt, d);
    }
    public Intent withResource(Resource r) {
        return new Intent(intentId, idempotencyKey, name, action, r, relatedResources,
                namespace, params, subject, issuedAt, expiresAt, decision);
    }
}
```

#### `BindCalculator.java`

```java
package com.tamojit.hearth.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Shared bind computation. Gateway and all domain services must use this exact class.
 * Golden test vectors: bind-vectors.json in src/test/resources.
 */
public final class BindCalculator {

    // Jackson 2.x, NOT the Boot default Jackson 3.
    private static final ObjectMapper CANON = JsonMapper.builder()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .build();

    private BindCalculator() {}

    /**
     * @param method      HTTP method (or "GRPC"), upper-cased
     * @param rawPath     percent-encoded path as the upstream service will receive it
     * @param rawQuery    raw query string (may be null)
     * @param checksum    value of X-Checksum-SHA256 header (may be null)
     * @param jsonBody    bounded JSON body bytes, or null/empty for streamed bodies
     */
    public static String bind(String method, String rawPath, String rawQuery,
                              String checksum, byte[] jsonBody) {
        String body = (jsonBody == null || jsonBody.length == 0)
                ? "" : hex(sha256(canonicalJson(jsonBody)));
        String canonical = String.join("\n",
                method.toUpperCase(),
                rawPath,
                sortedQuery(rawQuery),
                checksum == null ? "" : checksum.toLowerCase(),
                body);
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(sha256(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    static String sortedQuery(String q) {
        if (q == null || q.isEmpty()) return "";
        String[] parts = q.split("&");
        Arrays.sort(parts);
        return String.join("&", parts);
    }

    static byte[] canonicalJson(byte[] raw) {
        try {
            return CANON.writeValueAsBytes(CANON.readValue(raw, Object.class));
        } catch (IOException e) {
            throw new IllegalArgumentException("invalid json body", e);
        }
    }

    static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }
}
```

#### `JwtVerifier.java`

> Used by: gateway (access JWT), all domain services (context token), data plane (ticket). Replaces `jwtProcessorCustomizer` — works on Boot 4 / Spring Security 7 without framework coupling.

```java
package com.tamojit.hearth.common;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.*;

import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

public final class JwtVerifier {

    public record Spec(String typ, String issuer, String audience, Duration skew) {}

    public static class Rejected extends RuntimeException {
        public Rejected(String reason) { super(reason); }
    }
    public static class Unavailable extends RuntimeException {
        public Unavailable(Throwable cause) { super(cause); }
    }

    private final JWKSource<SecurityContext> jwks;
    private final Spec spec;

    public JwtVerifier(JWKSource<SecurityContext> jwks, Spec spec) {
        this.jwks = jwks;
        this.spec = spec;
    }

    public JWTClaimsSet verify(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWSHeader h = jwt.getHeader();

            if (!JWSAlgorithm.ES256.equals(h.getAlgorithm()))
                throw new Rejected("alg");
            if (h.getType() == null || !spec.typ().equals(h.getType().getType()))
                throw new Rejected("typ");

            List<JWK> keys = jwks.get(
                    new JWKSelector(new JWKMatcher.Builder()
                            .keyType(KeyType.EC)
                            .keyID(h.getKeyID())
                            .build()), null);
            if (keys.isEmpty()) throw new Rejected("kid");

            ECPublicKey pubKey = ((ECKey) keys.get(0)).toECPublicKey();
            if (!jwt.verify(new ECDSAVerifier(pubKey))) throw new Rejected("sig");

            JWTClaimsSet c = jwt.getJWTClaimsSet();
            if (!spec.issuer().equals(c.getIssuer())) throw new Rejected("iss");

            List<String> aud = c.getAudience();
            if (aud == null || !aud.contains(spec.audience())) throw new Rejected("aud");

            Date exp = c.getExpirationTime();
            if (exp == null || Instant.now().isAfter(exp.toInstant().plus(spec.skew())))
                throw new Rejected("exp");

            return c;
        } catch (KeySourceException e) {
            throw new Unavailable(e);
        } catch (ParseException | JOSEException e) {
            throw new Rejected("malformed: " + e.getMessage());
        }
    }
}
```

#### `DiskBackedJwkSource.java`

```java
package com.tamojit.hearth.common;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Wraps a Nimbus JWKSource with disk-persisted fallback.
 * On every successful fetch, merges keys by kid and writes atomically to
 * /var/hearth/jwks/{issuer-name}.json.
 * On KeySourceException, serves lastKnown, loading the file if memory is cold.
 */
public final class DiskBackedJwkSource implements JWKSource<SecurityContext> {
    private static final Logger log = LoggerFactory.getLogger(DiskBackedJwkSource.class);

    private final JWKSource<SecurityContext> delegate;
    private final Path cacheFile;
    private final List<JWK> lastKnown = new CopyOnWriteArrayList<>();

    public DiskBackedJwkSource(URL jwksUrl, String issuerName) {
        this.delegate = JWKSourceBuilder.create(jwksUrl)
                .retrying(true)
                .rateLimited(30_000)
                .build();
        Path dir = Path.of("/var/hearth/jwks");
        try { Files.createDirectories(dir); } catch (IOException ignored) {}
        this.cacheFile = dir.resolve(issuerName + ".json");
    }

    @Override
    public List<JWK> get(com.nimbusds.jose.jwk.JWKSelector selector, SecurityContext ctx)
            throws com.nimbusds.jose.KeySourceException {
        try {
            List<JWK> fresh = delegate.get(selector, ctx);
            mergeAndPersist(fresh);
            return fresh;
        } catch (com.nimbusds.jose.KeySourceException e) {
            log.warn("JWKS fetch failed, serving cached keys: {}", e.getMessage());
            if (lastKnown.isEmpty()) loadFromDisk();
            List<JWK> matching = selector.select(new JWKSet(lastKnown));
            if (matching.isEmpty()) throw e;
            return matching;
        }
    }

    private synchronized void mergeAndPersist(List<JWK> fresh) {
        Map<String, JWK> byKid = new LinkedHashMap<>();
        lastKnown.forEach(k -> byKid.put(k.getKeyID(), k));
        fresh.forEach(k -> byKid.put(k.getKeyID(), k));
        lastKnown.clear();
        lastKnown.addAll(byKid.values());
        try {
            Path tmp = cacheFile.resolveSibling(cacheFile.getFileName() + ".tmp");
            String json = new JWKSet(lastKnown).toString(false);
            Files.writeString(tmp, json, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(tmp, cacheFile, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException ex) {
            log.warn("Could not persist JWKS cache: {}", ex.getMessage());
        }
    }

    private synchronized void loadFromDisk() {
        try {
            if (Files.exists(cacheFile)) {
                String json = Files.readString(cacheFile);
                JWKSet set = JWKSet.parse(json);
                lastKnown.addAll(set.getKeys());
                log.info("Loaded {} JWKS keys from disk cache {}", lastKnown.size(), cacheFile);
            }
        } catch (IOException | ParseException ex) {
            log.error("Could not load JWKS disk cache: {}", ex.getMessage());
        }
    }
}
```

#### `ProblemDetails.java`

```java
package com.tamojit.hearth.common;

/** RFC 9457 problem body — a plain POJO. Each framework writes it with its own serialiser. */
public record ProblemDetails(
        String type, String title, int status, String code, String intentId, String traceId
) {
    public static ProblemDetails of(int status, String code) {
        return new ProblemDetails("about:blank",
                code.replace('_', ' ').toLowerCase(), status, code, null, null);
    }
    public ProblemDetails withIntentId(String id) {
        return new ProblemDetails(type, title, status, code, id, traceId);
    }
    public ProblemDetails withTraceId(String id) {
        return new ProblemDetails(type, title, status, code, intentId, id);
    }
}
```

#### `ScopeEnforcer.java`

```java
package com.tamojit.hearth.common;

/**
 * Scope values strictly bound to OWN, SHARED, and ANY.
 * GRANTED and ASSIGNED are dropped.
 */
public enum ScopeEnforcer {
    OWN {
        @Override public void enforce(String callerUsername, String resourceId, String namespace) {
            if (!resourceId.equals(callerUsername))
                throw new ScopeViolation("NOT_OWNER: resource=" + resourceId + " caller=" + callerUsername);
        }
    },
    SHARED {
        @Override public void enforce(String callerUsername, String resourceId, String namespace) {
            if (!"SHARED".equalsIgnoreCase(namespace))
                throw new ScopeViolation("NOT_SHARED_NAMESPACE: expected SHARED namespace but was " + namespace);
        }
    },
    ANY {
        @Override public void enforce(String callerUsername, String resourceId, String namespace) {
            // unrestricted within resource type
        }
    };

    public abstract void enforce(String callerUsername, String resourceId, String namespace);

    public static class ScopeViolation extends RuntimeException {
        public ScopeViolation(String msg) { super(msg); }
    }

    public static ScopeEnforcer of(String scopeName) {
        return valueOf(scopeName.toUpperCase());
    }
}
```

### 0.3 Test vectors: `src/test/resources/bind-vectors.json`

```json
[
  { "id": "plain-get",
    "method": "GET", "path": "/internal/nas/files/list", "query": "path=docs",
    "checksum": null, "body": null },
  { "id": "unsorted-query",
    "method": "GET", "path": "/internal/nas/files/list", "query": "b=2&a=1",
    "checksum": null, "body": null },
  { "id": "sorted-query-equiv",
    "method": "GET", "path": "/internal/nas/files/list", "query": "a=1&b=2",
    "checksum": null, "body": null, "equivTo": "unsorted-query" },
  { "id": "encoded-space",
    "method": "PUT", "path": "/internal/nas/files/my%20docs/report.pdf", "query": "",
    "checksum": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "body": null },
  { "id": "encoded-slash",
    "method": "PUT", "path": "/internal/nas/files/a%2Fb", "query": "",
    "checksum": null, "body": null,
    "note": "%2F must stay encoded, different from /a/b" },
  { "id": "json-body-ordered",
    "method": "POST", "path": "/internal/nas/uploads", "query": "",
    "checksum": null, "body": {"path": "/docs/x.pdf", "sizeBytes": 1024} },
  { "id": "json-body-unordered",
    "method": "POST", "path": "/internal/nas/uploads", "query": "",
    "checksum": null, "body": {"sizeBytes": 1024, "path": "/docs/x.pdf"},
    "equivTo": "json-body-ordered" },
  { "id": "null-query",
    "method": "GET", "path": "/internal/nas/files/list", "query": null,
    "checksum": null, "body": null },
  { "id": "checksum-lowercase",
    "method": "PUT", "path": "/internal/nas/files/x.txt", "query": "",
    "checksum": "ABCDEF", "body": null,
    "note": "checksum must be lowercased before hashing" }
]
```

---

## Phase 1: DB creation and seeding (Day-0)

### 1.1 `postgres-init/01-provision-databases.sh` (rewritten)

```bash
#!/bin/bash
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL

  -- auth-service DB
  DO \$\$
  BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'antar_auth') THEN
      CREATE ROLE antar_auth WITH LOGIN PASSWORD '${AUTH_DB_PASSWORD}';
    END IF;
  END \$\$;
  SELECT 'CREATE DATABASE antar_auth OWNER antar_auth'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'antar_auth') \gexec

  -- policy-registry DB
  DO \$\$
  BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'antar_policy') THEN
      CREATE ROLE antar_policy WITH LOGIN PASSWORD '${POLICY_DB_PASSWORD}';
    END IF;
  END \$\$;
  SELECT 'CREATE DATABASE antar_policy OWNER antar_policy'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'antar_policy') \gexec

  -- streaming DB (unchanged)
  DO \$\$
  BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'antar_streaming') THEN
      CREATE ROLE antar_streaming WITH LOGIN PASSWORD '${STREAMING_DB_PASSWORD}';
    END IF;
  END \$\$;
  SELECT 'CREATE DATABASE antar_streaming OWNER antar_streaming'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'antar_streaming') \gexec

EOSQL

# Seed auth DB
psql -v ON_ERROR_STOP=1 \
     --username antar_auth \
     --dbname antar_auth \
     --variable owner_username="${HEARTH_OWNER_USERNAME}" \
     --variable owner_password_hash="${HEARTH_OWNER_PASSWORD_HASH}" \
     --variable video_svc_hash="${VIDEO_SVC_SECRET_HASH}" \
     --variable encoding_svc_hash="${ENCODING_SVC_SECRET_HASH}" \
     --variable streaming_svc_hash="${STREAMING_SVC_SECRET_HASH}" \
     --variable gateway_svc_hash="${GATEWAY_SVC_SECRET_HASH}" \
     -f /docker-entrypoint-initdb.d/02-seed-auth.sql

# Seed policy DB
psql -v ON_ERROR_STOP=1 \
     --username antar_policy \
     --dbname antar_policy \
     -f /docker-entrypoint-initdb.d/03-seed-policy.sql
```

### 1.2 `postgres-init/02-seed-auth.sql`

```sql
CREATE TYPE user_role   AS ENUM ('OWNER', 'RESIDENT', 'GUEST');
CREATE TYPE user_status AS ENUM ('ACTIVE', 'SUSPENDED');

CREATE TABLE users (
  id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  username             VARCHAR(32)  NOT NULL UNIQUE,
  password_hash        TEXT         NOT NULL,
  role                 user_role    NOT NULL DEFAULT 'RESIDENT',
  status               user_status  NOT NULL DEFAULT 'ACTIVE',
  must_change_password BOOLEAN      NOT NULL DEFAULT FALSE,
  expires_at           TIMESTAMPTZ,
  created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
  CONSTRAINT users_username_format CHECK (username ~ '^[a-z0-9_-]{3,32}$')
);

CREATE TABLE sessions (
  id                UUID        PRIMARY KEY,
  user_id           UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id         VARCHAR(64),
  amr               TEXT[]      NOT NULL,
  refresh_hash      CHAR(43)    NOT NULL,
  prev_refresh_hash CHAR(43),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at        TIMESTAMPTZ NOT NULL,
  revoked_at        TIMESTAMPTZ,
  revoked_reason    VARCHAR(32)
);
CREATE INDEX idx_sessions_user ON sessions (user_id) WHERE revoked_at IS NULL;

-- Service principals are NOT users. No FK to users table.
CREATE TABLE service_clients (
  client_id    VARCHAR(64)  NOT NULL,
  audience     VARCHAR(64)  NOT NULL,
  secret_hash  VARCHAR(255) NOT NULL,
  scope        TEXT         NOT NULL,
  enabled      BOOLEAN      NOT NULL DEFAULT TRUE,
  PRIMARY KEY (client_id, audience)
);

-- Passkeys (Phase 1b)
CREATE TABLE credentials (
  credential_id BYTEA       PRIMARY KEY,
  user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key    BYTEA       NOT NULL,
  sign_count    BIGINT      NOT NULL DEFAULT 0,
  transports    TEXT[],
  label         VARCHAR(64),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed OWNER
INSERT INTO users (username, password_hash, role)
VALUES (:'owner_username', :'owner_password_hash', 'OWNER');

-- Seed service clients (scope: {resource}:{verb}:{path-glob})
INSERT INTO service_clients (client_id, audience, secret_hash, scope) VALUES
  ('video-service',    'nas-orchestrator', :'video_svc_hash',    'nas:write:raw/** nas:read:raw/**'),
  ('encoding-service', 'nas-orchestrator', :'encoding_svc_hash', 'nas:read:raw/** nas:write:encoded/**'),
  ('streaming-service','nas-orchestrator', :'streaming_svc_hash','nas:read:encoded/**'),
  ('api-gateway',      'element-registry', :'gateway_svc_hash',  'elements:read');
```

### 1.3 `postgres-init/03-seed-policy.sql`

```sql
CREATE TYPE policy_effect AS ENUM ('ALLOW', 'DENY');
-- Strictly bound to OWN, SHARED, ANY
CREATE TYPE policy_scope  AS ENUM ('OWN', 'SHARED', 'ANY');

-- rule_name: AAA.BBB.CCC matching the gateway manifest intent field.
-- resource_qualifier: NULL means "any qualifier".
-- No FK to users (separate DB). updated_by is a plain UUID reference.
CREATE TABLE policy_rules (
  id                 UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_name          TEXT          NOT NULL,
  domain             TEXT          NOT NULL,
  role               TEXT          NOT NULL,
  action             TEXT          NOT NULL,
  resource_type      TEXT          NOT NULL,
  resource_qualifier TEXT,
  scope              policy_scope  NOT NULL DEFAULT 'OWN',
  effect             policy_effect NOT NULL DEFAULT 'ALLOW',
  conditions         JSONB         NOT NULL DEFAULT '{}',
  priority           INT           NOT NULL DEFAULT 0,
  enabled            BOOLEAN       NOT NULL DEFAULT TRUE,
  created_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_by         UUID,
  UNIQUE NULLS NOT DISTINCT (domain, role, action, resource_type, resource_qualifier, scope, effect)
);

CREATE TABLE policy_meta (version BIGINT NOT NULL);
INSERT INTO policy_meta VALUES (1);

-- ── Seed: OWNER – all actions × all resource types (72 rows) ───────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, scope, effect)
SELECT
  lower(d) || '.' || lower(r) || '.' || lower(a),
  d, 'OWNER', a, r, 'ANY', 'ALLOW'
FROM
  unnest(ARRAY['NAS','ELEMENT']) d,
  unnest(ARRAY['LIST','READ','CREATE','UPDATE','DELETE','SHARE','CONTROL','STREAM','MANAGE']) a,
  unnest(ARRAY['WORKSPACE','SHARED','MEDIA','ELEMENT','AREA','USER','GUEST','POLICY']) r;

-- ── Seed: RESIDENT – own workspace (5 rows, NAS domain) ───────────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, scope, effect)
SELECT 'nas.workspace.' || lower(a), 'NAS', 'RESIDENT', a, 'WORKSPACE', 'OWN', 'ALLOW'
FROM unnest(ARRAY['LIST','READ','CREATE','UPDATE','DELETE']) a;

-- ── Seed: RESIDENT – shared workspace (SHARED scope) ──────────────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, resource_qualifier, scope, effect) VALUES
  ('nas.shared.read',   'NAS', 'RESIDENT', 'READ',   'SHARED', NULL, 'SHARED', 'ALLOW'),
  ('nas.shared.update', 'NAS', 'RESIDENT', 'UPDATE', 'SHARED', NULL, 'SHARED', 'ALLOW');

-- ── Seed: RESIDENT – media and element (ANY scope) ─────────────────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, scope, effect) VALUES
  ('nas.media.stream',       'NAS',     'RESIDENT', 'STREAM',  'MEDIA',   'ANY', 'ALLOW'),
  ('element.device.control', 'ELEMENT', 'RESIDENT', 'CONTROL', 'ELEMENT', 'ANY', 'ALLOW'),
  ('element.camera.stream',  'ELEMENT', 'RESIDENT', 'STREAM',  'ELEMENT', 'ANY', 'ALLOW');

-- ── Seed: GUEST – shared read only ────────────────────────────────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, scope, effect) VALUES
  ('nas.shared.guest.read', 'NAS', 'GUEST', 'READ', 'SHARED', NULL, 'SHARED', 'ALLOW');

-- ── Seed: GUEST – element CAMERA DENY (explicit) ──────────────────────────
INSERT INTO policy_rules (rule_name, domain, role, action, resource_type, resource_qualifier, scope, effect) VALUES
  ('element.camera.guest.deny', 'ELEMENT', 'GUEST', 'STREAM', 'ELEMENT', 'CAMERA', 'ANY', 'DENY');

-- Expected total: 72 (OWNER) + 5 (RESIDENT workspace) + 2 (RESIDENT shared)
--               + 3 (RESIDENT media/element) + 1 (GUEST shared) + 1 (GUEST camera deny) = 84
```

> **Design note:** Policy scopes are strictly bound to `OWN`, `SHARED`, and `ANY`. `resource_grants` table and `GRANTED`/`ASSIGNED` scopes are completely removed.

---

## Phase 2: auth-service (rewritten from scratch)

### 2.1 Delete all existing source under `auth-service/src/`

Remove: `JwtService.java`, `ServiceAccountBootstrap.java`, `AuthController.java` (old), `AuthService.java` (old), `User.java` (old), all DTOs, all Flyway scripts.

Keep (temporarily until P7): `AuthGrpcServer.java` — replace with `LegacyValidateTokenServer.java`.

### 2.2 `auth-service/pom.xml` (full replacement)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
           https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>4.1.1</version>
    <relativePath/>
  </parent>
  <groupId>com.tamojit</groupId>
  <artifactId>auth-service</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <name>auth-service</name>

  <properties>
    <java.version>21</java.version>
    <nimbus.version>9.37.3</nimbus.version>
  </properties>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.grpc</groupId>
        <artifactId>spring-grpc-dependencies</artifactId>
        <version>1.0.3</version><type>pom</type><scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <dependencies>
    <dependency>
      <groupId>com.tamojit</groupId>
      <artifactId>hearth-auth-common</artifactId>
      <version>1.0.0</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-webmvc</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>
    <!-- gRPC — legacy ValidateToken until P7 -->
    <dependency>
      <groupId>org.springframework.grpc</groupId>
      <artifactId>spring-grpc-spring-boot-starter</artifactId>
    </dependency>
    <dependency>
      <groupId>javax.annotation</groupId>
      <artifactId>javax.annotation-api</artifactId>
      <version>1.3.2</version>
    </dependency>
    <dependency>
      <groupId>org.postgresql</groupId>
      <artifactId>postgresql</artifactId><scope>runtime</scope>
    </dependency>
    <dependency>
      <groupId>org.springframework.kafka</groupId>
      <artifactId>spring-kafka</artifactId>
    </dependency>
    <dependency>
      <groupId>com.nimbusds</groupId>
      <artifactId>nimbus-jose-jwt</artifactId>
      <version>${nimbus.version}</version>
    </dependency>
    <!-- Argon2 (spring-security-crypto; needs BouncyCastle) -->
    <dependency>
      <groupId>org.springframework.security</groupId>
      <artifactId>spring-security-crypto</artifactId>
    </dependency>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78.1</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId><scope>test</scope>
    </dependency>
  </dependencies>

  <build>
    <extensions>
      <extension>
        <groupId>kr.motd.maven</groupId>
        <artifactId>os-maven-plugin</artifactId><version>1.7.1</version>
      </extension>
    </extensions>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
      <plugin>
        <groupId>org.xolstice.maven.plugins</groupId>
        <artifactId>protobuf-maven-plugin</artifactId>
        <version>0.6.1</version>
        <configuration>
          <protoSourceRoot>${project.basedir}/../proto</protoSourceRoot>
          <protocArtifact>com.google.protobuf:protoc:4.29.3:exe:${os.detected.classifier}</protocArtifact>
          <pluginId>grpc-java</pluginId>
          <pluginArtifact>io.grpc:protoc-gen-grpc-java:1.71.0:exe:${os.detected.classifier}</pluginArtifact>
        </configuration>
        <executions><execution><goals><goal>compile</goal><goal>compile-custom</goal></goals></execution></executions>
      </plugin>
    </plugins>
  </build>
</project>
```

### 2.3 `auth-service/src/main/resources/application.properties`

```properties
spring.application.name=auth-service
server.port=9000

spring.datasource.url=${AUTH_DB_URL}
spring.datasource.username=antar_auth
spring.datasource.password=${AUTH_DB_PASSWORD}
spring.jpa.hibernate.ddl-auto=validate
spring.jpa.open-in-view=false
spring.flyway.enabled=false

spring.data.redis.host=${REDIS_HOST:redis}
spring.data.redis.port=6379
spring.data.redis.password=${REDIS_PASSWORD:}

spring.kafka.bootstrap-servers=${KAFKA_BOOTSTRAP:kafka:29092}
spring.kafka.producer.key-serializer=org.apache.kafka.common.serialization.StringSerializer
spring.kafka.producer.value-serializer=org.springframework.kafka.support.serializer.JsonSerializer

auth.keys.dir=${AUTH_KEYS_DIR:/run/secrets/auth-keys}
auth.keys.current-kid=${AUTH_CURRENT_KID:auth-2026-11}

spring.grpc.server.port=4091

management.endpoints.web.exposure.include=health,info
```

### 2.4 Package structure

```
src/main/java/com/tamojit/authservice/
├── AuthServiceApplication.java
├── config/
│   ├── AuthKeys.java           ← loads EC key pair from PEM files
│   ├── PasswordConfig.java     ← DelegatingPasswordEncoder (bcrypt + Argon2)
│   ├── RedisConfig.java
│   ├── KafkaConfig.java
│   └── WebConfig.java
├── model/
│   ├── User.java               ← @Entity, UUID PK, user_role ENUM
│   ├── Session.java            ← @Entity
│   └── ServiceClient.java      ← @Entity
├── repository/
│   ├── UserRepository.java
│   ├── SessionRepository.java  ← findByIdForUpdate (SELECT...FOR UPDATE)
│   └── ServiceClientRepository.java
├── security/
│   ├── AccessTokenIssuer.java  ← ES256, typ=at+jwt
│   └── RefreshTokenUtil.java
├── service/
│   ├── SessionService.java     ← create, rotate (reuse detection), revoke
│   └── AuthService.java        ← login orchestration
├── controller/
│   ├── AuthController.java     ← /api/v1/auth/login, /refresh, /logout
│   ├── JwksController.java     ← GET /.well-known/jwks.json
│   └── ServiceTokenController.java  ← POST /oauth/token
├── dto/
│   ├── LoginRequest.java
│   ├── LoginResponse.java      ← { accessToken, refreshToken, expiresIn }
│   ├── RefreshRequest.java
│   ├── ClientCredentialsRequest.java
│   └── ClientCredentialsResponse.java
├── event/
│   └── DenylistPublisher.java  ← Redis deny:sid + Kafka session.revoked
└── grpc/
    └── LegacyValidateTokenServer.java  ← thin bridge; removed in P7
```

### 2.5 Key files

#### `config/AuthKeys.java`

```java
package com.tamojit.authservice.config;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

@Component
public class AuthKeys {
    private static final Logger log = LoggerFactory.getLogger(AuthKeys.class);

    @Value("${auth.keys.dir}") private String keysDir;
    @Value("${auth.keys.current-kid}") private String currentKid;

    private final Map<String, ECKey> keyMap = new LinkedHashMap<>();
    private ECKey currentKey;

    @PostConstruct
    public void load() throws Exception {
        Path dir = Path.of(keysDir);
        if (!Files.isDirectory(dir)) {
            log.warn("auth.keys.dir not found — generating ephemeral in-memory key (dev only)");
            ECKey k = new ECKeyGenerator(Curve.P_256).keyID(currentKid).generate();
            keyMap.put(currentKid, k);
            currentKey = k;
            return;
        }
        try (var stream = Files.list(dir)) {
            stream.filter(p -> p.toString().endsWith(".pem")).forEach(p -> {
                try {
                    String kid = p.getFileName().toString().replace(".pem", "");
                    String pem = Files.readString(p, StandardCharsets.UTF_8);
                    ECKey k = JWK.parseFromPEMEncodedObjects(pem).toECKey();
                    keyMap.put(kid, k);
                    log.info("Loaded auth key: {}", kid);
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to load auth key " + p, e);
                }
            });
        }
        currentKey = Objects.requireNonNull(keyMap.get(currentKid),
                "auth.keys.current-kid=" + currentKid + " not found in " + keysDir);
    }

    public String sign(JWTClaimsSet claims, String typ) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(currentKey.getKeyID())
                .type(new JOSEObjectType(typ))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(currentKey));
        return jwt.serialize();
    }

    public JWKSet publicJwkSet() {
        List<JWK> pubs = keyMap.values().stream().map(k -> (JWK) k.toPublicJWK()).toList();
        return new JWKSet(pubs);
    }
    public ECKey current() { return currentKey; }
}
```

#### `security/AccessTokenIssuer.java`

```java
package com.tamojit.authservice.security;

import com.nimbusds.jwt.JWTClaimsSet;
import com.tamojit.authservice.config.AuthKeys;
import com.tamojit.authservice.model.User;
import com.tamojit.hearth.common.Hearth;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
public class AccessTokenIssuer {
    private final AuthKeys keys;
    public AccessTokenIssuer(AuthKeys keys) { this.keys = keys; }

    public String issue(User u, UUID sessionId, List<String> amr) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet.Builder c = new JWTClaimsSet.Builder()
                    .issuer(Hearth.ISS_AUTH).audience("hearth-gateway")
                    .subject(u.getId().toString())
                    .claim("username", u.getUsername()).claim("role", u.getRole().name())
                    .claim("sid", sessionId.toString()).claim("amr", amr)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(900)))
                    .jwtID(UUID.randomUUID().toString());
            if (u.isMustChangePassword()) c.claim("scope", "pwd-change");
            return keys.sign(c.build(), "at+jwt");
        } catch (Exception e) {
            throw new IllegalStateException("Access token signing failed", e);
        }
    }

    public String issueService(String clientId, String audience, String scope) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(Hearth.ISS_AUTH).audience(audience)
                    .subject("svc:" + clientId).claim("scope", scope)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(600)))
                    .jwtID(UUID.randomUUID().toString()).build();
            return keys.sign(claims, "at+jwt");
        } catch (Exception e) {
            throw new IllegalStateException("Service token signing failed", e);
        }
    }
}
```

#### `service/SessionService.java`

```java
package com.tamojit.authservice.service;

import com.tamojit.authservice.event.DenylistPublisher;
import com.tamojit.authservice.model.*;
import com.tamojit.authservice.repository.*;
import com.tamojit.authservice.security.AccessTokenIssuer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.*;
import java.util.*;

@Service
public class SessionService {
    private final SessionRepository sessions;
    private final AccessTokenIssuer issuer;
    private final DenylistPublisher denylist;

    public SessionService(SessionRepository sessions, AccessTokenIssuer issuer,
                          DenylistPublisher denylist) {
        this.sessions = sessions; this.issuer = issuer; this.denylist = denylist;
    }

    @Transactional
    public TokenPair create(User u, String deviceId) {
        UUID sid = UUID.randomUUID();
        String rawRefresh = sid + "." + randomHex(32);
        Session s = new Session();
        s.setId(sid); s.setUser(u); s.setDeviceId(deviceId);
        s.setAmr(new String[]{"pwd"}); s.setRefreshHash(sha256b64(rawRefresh));
        s.setExpiresAt(Instant.now().plus(Duration.ofDays(7)));
        sessions.save(s);
        return new TokenPair(issuer.issue(u, sid, List.of("pwd")), rawRefresh, 900);
    }

    @Transactional
    public TokenPair rotate(String presented) {
        int dot = presented.indexOf('.');
        if (dot < 0) throw new InvalidRefreshException();
        UUID sid;
        try { sid = UUID.fromString(presented.substring(0, dot)); }
        catch (IllegalArgumentException e) { throw new InvalidRefreshException(); }

        Session s = sessions.findByIdForUpdate(sid).orElseThrow(InvalidRefreshException::new);
        if (s.getRevokedAt() != null || s.getExpiresAt().isBefore(Instant.now()))
            throw new InvalidRefreshException();

        String h = sha256b64(presented);
        if (h.equals(s.getRefreshHash())) {
            String next = sid + "." + randomHex(32);
            s.setPrevRefreshHash(s.getRefreshHash());
            s.setRefreshHash(sha256b64(next));
            s.setLastUsedAt(Instant.now());
            sessions.save(s);
            return new TokenPair(issuer.issue(s.getUser(), sid, List.of(s.getAmr())), next, 900);
        }
        if (h.equals(s.getPrevRefreshHash())) {
            revoke(s, "REFRESH_REUSE");
        }
        throw new InvalidRefreshException();
    }

    @Transactional
    public void revoke(UUID sessionId, String reason) {
        sessions.findById(sessionId).ifPresent(s -> revoke(s, reason));
    }

    public void revoke(Session s, String reason) {
        s.setRevokedAt(Instant.now()); s.setRevokedReason(reason);
        sessions.save(s);
        denylist.deny(s.getId().toString(), reason);
    }

    private static String sha256b64(String input) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    private static String randomHex(int bytes) {
        byte[] b = new byte[bytes]; new SecureRandom().nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    public record TokenPair(String accessToken, String refreshToken, long expiresIn) {}
    public static class InvalidRefreshException extends RuntimeException {
        public InvalidRefreshException() { super("invalid refresh token"); }
    }
}
```

#### `event/DenylistPublisher.java`

```java
package com.tamojit.authservice.event;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import java.time.Duration;
import java.util.Map;

@Component
public class DenylistPublisher {
    private final StringRedisTemplate redis;
    private final KafkaTemplate<String, Object> kafka;

    public DenylistPublisher(StringRedisTemplate redis, KafkaTemplate<String, Object> kafka) {
        this.redis = redis; this.kafka = kafka;
    }

    /** Deny a session. TTL = 7 h = max ticket lifetime + margin. */
    public void deny(String sid, String reason) {
        redis.opsForValue().set("deny:sid:" + sid, reason, Duration.ofHours(7));
        kafka.send("session.revoked", sid, Map.of("sid", sid, "reason", reason));
    }
}
```

#### `controller/AuthController.java`

```java
package com.tamojit.authservice.controller;

import com.tamojit.authservice.dto.*;
import com.tamojit.authservice.model.User;
import com.tamojit.authservice.repository.UserRepository;
import com.tamojit.authservice.service.SessionService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final UserRepository users;
    private final SessionService sessions;
    private final PasswordEncoder encoder;

    public AuthController(UserRepository users, SessionService sessions, PasswordEncoder encoder) {
        this.users = users; this.sessions = sessions; this.encoder = encoder;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest req) {
        User u = users.findByUsername(req.username())
                .filter(found -> encoder.matches(req.password(), found.getPasswordHash()))
                .orElseThrow(() -> new AuthException("INVALID_CREDENTIALS", 401));

        if (u.getStatus() != User.UserStatus.ACTIVE)
            throw new AuthException("ACCOUNT_SUSPENDED", 403);
        if (u.getExpiresAt() != null && u.getExpiresAt().isBefore(Instant.now()))
            throw new AuthException("ACCOUNT_EXPIRED", 403);

        // Re-hash to Argon2 if still bcrypt
        if (encoder.upgradeEncoding(u.getPasswordHash())) {
            u.setPasswordHash(encoder.encode(req.password()));
            users.save(u);
        }

        SessionService.TokenPair pair = sessions.create(u, req.deviceId());
        return ResponseEntity.ok(new LoginResponse(pair.accessToken(), pair.refreshToken(), pair.expiresIn()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshRequest req) {
        SessionService.TokenPair pair = sessions.rotate(req.refreshToken());
        return ResponseEntity.ok(new LoginResponse(pair.accessToken(), pair.refreshToken(), pair.expiresIn()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("X-Session-Id") String sid) {
        sessions.revoke(UUID.fromString(sid), "LOGOUT");
        return ResponseEntity.noContent().build();
    }

    public static class AuthException extends RuntimeException {
        private final int status;
        public AuthException(String msg, int status) { super(msg); this.status = status; }
        public int getStatus() { return status; }
    }
}
```

#### `controller/JwksController.java`

```java
package com.tamojit.authservice.controller;

import com.tamojit.authservice.config.AuthKeys;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
public class JwksController {
    private final AuthKeys keys;
    public JwksController(AuthKeys keys) { this.keys = keys; }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "public, max-age=300")
                .contentType(MediaType.APPLICATION_JSON)
                .body(keys.publicJwkSet().toJSONObject());
    }
}
```

#### `controller/ServiceTokenController.java`

```java
package com.tamojit.authservice.controller;

import com.tamojit.authservice.dto.*;
import com.tamojit.authservice.model.ServiceClient;
import com.tamojit.authservice.repository.ServiceClientRepository;
import com.tamojit.authservice.security.AccessTokenIssuer;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@RequestMapping("/oauth")
public class ServiceTokenController {
    private final ServiceClientRepository clients;
    private final PasswordEncoder encoder;
    private final AccessTokenIssuer issuer;

    public ServiceTokenController(ServiceClientRepository clients, PasswordEncoder encoder,
                                   AccessTokenIssuer issuer) {
        this.clients = clients; this.encoder = encoder; this.issuer = issuer;
    }

    @PostMapping("/token")
    public ResponseEntity<?> token(@Valid @RequestBody ClientCredentialsRequest req) {
        if (!"client_credentials".equals(req.grantType()))
            return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));

        ServiceClient c = clients.findByClientIdAndAudience(req.clientId(), req.audience())
                .orElseThrow(() -> new AuthController.AuthException("INVALID_CLIENT", 401));
        if (!c.isEnabled()) throw new AuthController.AuthException("CLIENT_DISABLED", 401);
        if (!encoder.matches(req.clientSecret(), c.getSecretHash()))
            throw new AuthController.AuthException("INVALID_CLIENT", 401);

        // Validate scope is a subset of allowed
        Set<String> allowedSet = Set.of(c.getScope().split(" "));
        if (req.scope() != null) {
            for (String s : req.scope().split(" ")) {
                if (!s.isBlank() && !allowedSet.contains(s))
                    return ResponseEntity.badRequest()
                            .body(Map.of("error", "invalid_scope", "detail", s));
            }
        }

        String effectiveScope = req.scope() != null ? req.scope() : c.getScope();
        String token = issuer.issueService(req.clientId(), req.audience(), effectiveScope);
        return ResponseEntity.ok(new ClientCredentialsResponse(token, 600, "Bearer", effectiveScope));
    }
}
```

#### `grpc/LegacyValidateTokenServer.java` (kept until P7)

```java
package com.tamojit.authservice.grpc;

import com.tamojit.authservice.config.AuthKeys;
import com.tamojit.grpc.auth.*;
import com.tamojit.hearth.common.*;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import io.grpc.stub.StreamObserver;
import org.springframework.grpc.server.service.GrpcService;
import java.time.Duration;

@GrpcService
public class LegacyValidateTokenServer extends AuthServiceGrpc.AuthServiceImplBase {
    private final AuthKeys keys;
    public LegacyValidateTokenServer(AuthKeys keys) { this.keys = keys; }

    @Override
    public void validateToken(ValidateTokenRequest request,
                              StreamObserver<ValidateTokenResponse> resp) {
        // DO NOT log request — it contains the token
        try {
            JwtVerifier verifier = new JwtVerifier(
                    new ImmutableJWKSet<>(keys.publicJwkSet()),
                    new JwtVerifier.Spec("at+jwt", "hearth-auth", "hearth-gateway",
                            Duration.ofSeconds(5)));
            JWTClaimsSet c = verifier.verify(request.getToken());
            resp.onNext(ValidateTokenResponse.newBuilder()
                    .setValid(true).setUserId(c.getSubject())
                    .setUsername(c.getStringClaim("username"))
                    .setRole(c.getStringClaim("role")).build());
        } catch (Exception e) {
            resp.onNext(ValidateTokenResponse.newBuilder().setValid(false).build());
        }
        resp.onCompleted();
    }
}
```

#### DTO records

```java
// LoginRequest.java
public record LoginRequest(@NotBlank String username, @NotBlank String password, String deviceId) {}

// LoginResponse.java
public record LoginResponse(String accessToken, String refreshToken, long expiresIn) {}

// RefreshRequest.java
public record RefreshRequest(@NotBlank String refreshToken) {}

// ClientCredentialsRequest.java
public record ClientCredentialsRequest(
    @NotBlank String grantType, @NotBlank String clientId,
    @NotBlank String clientSecret, @NotBlank String audience, String scope) {}

// ClientCredentialsResponse.java
public record ClientCredentialsResponse(String accessToken, long expiresIn, String tokenType, String scope) {}
```

#### `config/PasswordConfig.java`

```java
package com.tamojit.authservice.config;

import org.springframework.context.annotation.*;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.*;
import java.util.Map;

@Configuration
public class PasswordConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        Map<String, PasswordEncoder> encoders = Map.of(
                "bcrypt", new BCryptPasswordEncoder(12),
                "argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        return new DelegatingPasswordEncoder("argon2", encoders);
    }
}
```

### 2.6 `auth-service/.env`

```env
AUTH_DB_URL=jdbc:postgresql://postgres:5432/antar_auth
AUTH_DB_PASSWORD=changeme_auth
REDIS_HOST=redis
REDIS_PASSWORD=
KAFKA_BOOTSTRAP=kafka:29092
AUTH_KEYS_DIR=/run/secrets/auth-keys
AUTH_CURRENT_KID=auth-2026-11
```

### 2.7 `auth-service/Dockerfile`

```dockerfile
FROM eclipse-temurin:21-jdk AS build
WORKDIR /build
COPY hearth-auth-common /hearth-auth-common
RUN mvn -q -f /hearth-auth-common/pom.xml install -DskipTests
COPY auth-service /auth-service
RUN mvn -q -f /auth-service/pom.xml package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /auth-service/target/*.jar app.jar
EXPOSE 9000 4091
ENTRYPOINT ["java", "-jar", "app.jar"]
```

> Build context in compose **must** be the repo root (`context: .`).

---

## Phase 3: policy-registry

### 3.1 `proto/policy.proto`

```protobuf
syntax = "proto3";
package com.tamojit.grpc.policy;
option java_multiple_files = true;
option java_package = "com.tamojit.grpc.policy";

service Policy {
  rpc Decide(DecideRequest) returns (DecideResponse);
}

message DecideRequest {
  string domain     = 1;   // NAS | ELEMENT
  Subject subject   = 2;
  string action     = 3;
  Resource resource = 4;
  string namespace  = 5;   // OWNED | SHARED — from route metadata, not part of rule key
  string rule_name  = 6;   // AAA.BBB.CCC hint, matches gateway manifest intent field
}
message Subject  { string user_id = 1; string username = 2; string role = 3; }
message Resource {
  string type = 1; string id = 2; string qualifier = 3;
  map<string, string> attrs = 4;
}
message DecideResponse {
  string effect      = 1;   // ALLOW | DENY
  string scope       = 2;   // OWN | SHARED | ANY (empty on DENY)
  string reason_code = 3;   // logged internally, not sent to client
}
```

### 3.2 `policy-registry/src/main/resources/application.properties`

```properties
spring.application.name=policy-registry

spring.datasource.url=${POLICY_DB_URL}
spring.datasource.username=antar_policy
spring.datasource.password=${POLICY_DB_PASSWORD}
spring.jpa.hibernate.ddl-auto=validate
spring.jpa.open-in-view=false
spring.flyway.enabled=false

spring.kafka.bootstrap-servers=${KAFKA_BOOTSTRAP:kafka:29092}
spring.kafka.consumer.group-id=policy-registry
spring.kafka.consumer.auto-offset-reset=earliest

spring.grpc.server.port=9100

management.endpoints.web.exposure.include=health
```

### 3.3 Key source files

#### `model/PolicyRule.java`

```java
package com.tamojit.policyregistry.model;

import jakarta.persistence.*;
import java.util.UUID;

@Entity @Table(name = "policy_rules")
public class PolicyRule {
    @Id private UUID id;
    @Column(name = "rule_name", nullable = false) private String ruleName;
    @Column(nullable = false) private String domain;
    @Column(nullable = false) private String role;
    @Column(nullable = false) private String action;
    @Column(name = "resource_type", nullable = false) private String resourceType;
    @Column(name = "resource_qualifier") private String resourceQualifier;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private PolicyScope scope;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private PolicyEffect effect;
    @Column(nullable = false) private boolean enabled = true;
    @Column(nullable = false) private int priority = 0;

    public enum PolicyScope  { OWN, SHARED, ANY }
    public enum PolicyEffect { ALLOW, DENY }

    public UUID getId()                   { return id; }
    public String getRuleName()           { return ruleName; }
    public String getDomain()             { return domain; }
    public String getRole()               { return role; }
    public String getAction()             { return action; }
    public String getResourceType()       { return resourceType; }
    public String getResourceQualifier()  { return resourceQualifier; }
    public PolicyScope getScope()         { return scope; }
    public PolicyEffect getEffect()       { return effect; }
    public boolean isEnabled()            { return enabled; }
    public int getPriority()              { return priority; }
}
```

#### `engine/DecisionEngine.java`

```java
package com.tamojit.policyregistry.engine;

import com.tamojit.grpc.policy.*;
import com.tamojit.policyregistry.model.PolicyRule;
import org.springframework.stereotype.Component;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class DecisionEngine {
    private final AtomicReference<RuleSnapshot> snapshot = new AtomicReference<>(RuleSnapshot.EMPTY);

    public void setSnapshot(RuleSnapshot s) { snapshot.set(s); }
    public RuleSnapshot getSnapshot()       { return snapshot.get(); }

    public DecideResponse decide(DecideRequest req) {
        String domain    = req.getDomain();
        String role      = req.getSubject().getRole();
        String action    = req.getAction();
        String resType   = req.getResource().getType();
        String qualifier = req.getResource().getQualifier();

        List<PolicyRule> matching = snapshot.get().rulesForDomain(domain).stream()
                .filter(r -> r.getRole().equalsIgnoreCase(role))
                .filter(r -> r.getAction().equalsIgnoreCase(action))
                .filter(r -> r.getResourceType().equalsIgnoreCase(resType))
                .filter(r -> r.getResourceQualifier() == null
                          || r.getResourceQualifier().equalsIgnoreCase(qualifier))
                .toList();

        if (matching.isEmpty())
            return DecideResponse.newBuilder().setEffect("DENY").setReasonCode("NO_MATCHING_RULE").build();

        boolean denied = matching.stream().anyMatch(r -> r.getEffect() == PolicyRule.PolicyEffect.DENY);
        if (denied)
            return DecideResponse.newBuilder().setEffect("DENY").setReasonCode("EXPLICIT_DENY").build();

        PolicyRule best = matching.stream()
                .filter(r -> r.getEffect() == PolicyRule.PolicyEffect.ALLOW)
                .max(Comparator.comparingInt(PolicyRule::getPriority)
                        .thenComparing(r -> r.getResourceQualifier() != null)
                        .thenComparing(r -> scopeBreadth(r.getScope())))
                .orElse(null);

        if (best == null)
            return DecideResponse.newBuilder().setEffect("DENY").setReasonCode("NO_ALLOW_RULE").build();

        return DecideResponse.newBuilder()
                .setEffect("ALLOW").setScope(best.getScope().name())
                .setReasonCode("RULE:" + best.getRuleName()).build();
    }

    private int scopeBreadth(PolicyRule.PolicyScope s) {
        return switch (s) { case OWN -> 0; case SHARED -> 1; case ANY -> 2; };
    }
}
```

#### `engine/RuleSnapshot.java`

```java
package com.tamojit.policyregistry.engine;

import com.tamojit.policyregistry.model.PolicyRule;
import java.util.*;

public record RuleSnapshot(Map<String, List<PolicyRule>> byDomain) {
    public static final RuleSnapshot EMPTY = new RuleSnapshot(Map.of());

    public List<PolicyRule> rulesForDomain(String domain) {
        return byDomain.getOrDefault(domain.toUpperCase(), List.of());
    }

    public static RuleSnapshot from(List<PolicyRule> all) {
        Map<String, List<PolicyRule>> map = new HashMap<>();
        for (PolicyRule r : all) {
            if (r.isEnabled())
                map.computeIfAbsent(r.getDomain().toUpperCase(), k -> new ArrayList<>()).add(r);
        }
        return new RuleSnapshot(Collections.unmodifiableMap(map));
    }
}
```

#### `engine/SnapshotRefresher.java`

```java
package com.tamojit.policyregistry.engine;

import com.tamojit.policyregistry.repository.PolicyRuleRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class SnapshotRefresher {
    private static final Logger log = LoggerFactory.getLogger(SnapshotRefresher.class);
    private static final long GRACE_WINDOW_SECONDS = 300;

    private final PolicyRuleRepository repo;
    private final DecisionEngine engine;
    private final AtomicReference<Instant> lastSuccess = new AtomicReference<>();

    public SnapshotRefresher(PolicyRuleRepository repo, DecisionEngine engine) {
        this.repo = repo; this.engine = engine;
    }

    @PostConstruct public void loadOnStartup() { refresh("startup"); }

    @KafkaListener(topics = "policy.changed", groupId = "policy-registry")
    public void onPolicyChanged(String domain) { refresh("kafka:" + domain); }

    @Scheduled(fixedDelay = 60_000) public void scheduledRefresh() { refresh("scheduled"); }

    private void refresh(String reason) {
        try {
            var rules = repo.findAllByEnabledTrue();
            engine.setSnapshot(RuleSnapshot.from(rules));
            lastSuccess.set(Instant.now());
            log.info("Policy snapshot refreshed ({}): {} rules", reason, rules.size());
        } catch (Exception e) {
            Instant last = lastSuccess.get();
            if (last != null && Instant.now().isBefore(last.plusSeconds(GRACE_WINDOW_SECONDS))) {
                log.warn("Refresh failed ({}), serving stale snapshot: {}", reason, e.getMessage());
            } else {
                log.error("Refresh failed and grace window expired — failing closed", e);
                engine.setSnapshot(RuleSnapshot.EMPTY);
            }
        }
    }
}
```

#### `grpc/PolicyGrpcServer.java`

```java
package com.tamojit.policyregistry.grpc;

import com.tamojit.grpc.policy.*;
import com.tamojit.policyregistry.engine.DecisionEngine;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.springframework.grpc.server.service.GrpcService;

@GrpcService
public class PolicyGrpcServer extends PolicyGrpc.PolicyImplBase {
    private final DecisionEngine engine;
    public PolicyGrpcServer(DecisionEngine engine) { this.engine = engine; }

    @Override
    public void decide(DecideRequest request, StreamObserver<DecideResponse> responseObserver) {
        String domain = request.getDomain();
        if (domain == null || (!domain.equals("NAS") && !domain.equals("ELEMENT"))) {
            responseObserver.onError(Status.INVALID_ARGUMENT
                    .withDescription("domain must be NAS or ELEMENT").asRuntimeException());
            return;
        }
        try {
            responseObserver.onNext(engine.decide(request));
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(Status.INTERNAL.withCause(e).asRuntimeException());
        }
    }
}
```

---

## Phase 4: api-gateway

### 4.1 Key Boot 4 deltas

| Issue | Fix |
|---|---|
| Gateway starter artifact | Use `spring-cloud-starter-gateway-server-webflux`, not `spring-cloud-starter-gateway` |
| Properties path | `spring.cloud.gateway.server.webflux.httpclient.*` and `spring.cloud.gateway.server.webflux.routes` |
| `jwtProcessorCustomizer` | Replaced with `JwtVerifier` from `hearth-auth-common` in `AuthenticationFilter` |
| Reactive gRPC | Wrap `PolicyGrpc.PolicyFutureStub` in `Mono.fromFuture(...)` |
| Jackson conflict | Pin `jackson-databind:2.17.2` explicitly in pom; needed by `hearth-auth-common`'s `BindCalculator` |

### 4.2 `api-gateway/pom.xml` (critical entries)

```xml
<!-- Boot 4 Gateway — WebFlux-based -->
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-gateway-server-webflux</artifactId>
</dependency>

<dependency>
  <groupId>com.tamojit</groupId>
  <artifactId>hearth-auth-common</artifactId>
  <version>1.0.0</version>
</dependency>

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-redis-reactive</artifactId>
</dependency>

<!-- Jackson 2 for BindCalculator -->
<dependency>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
  <version>2.17.2</version>
</dependency>

<dependency>
  <groupId>com.nimbusds</groupId>
  <artifactId>nimbus-jose-jwt</artifactId>
  <version>9.37.3</version>
</dependency>

<!-- Spring Cloud BOM 2025.1.4 in dependencyManagement -->
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework.cloud</groupId>
      <artifactId>spring-cloud-dependencies</artifactId>
      <version>2025.1.4</version>
      <type>pom</type><scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

### 4.3 `api-gateway/src/main/resources/application.yml` (key sections)

```yaml
spring:
  cloud:
    gateway:
      server:
        webflux:
          httpclient:
            connect-timeout: 2000
          routes:
            - id: nas-file-list
              uri: http://nas-orchestrator:8081
              predicates: [Path=/api/v1/nas/files/list, Method=GET]
              metadata:
                hearth:
                  intent: nas.workspace.list
                  action: LIST
                  domain: NAS
                  class: query
                  audience: nas-orchestrator
                  resourceType: WORKSPACE
                  resourceId: "{username}"
                  namespace: OWNED
                  upstreamPath: /internal/nas/files/list

            - id: nas-file-create
              uri: http://nas-orchestrator:8081
              predicates: [Path=/api/v1/nas/files/{*path}, Method=PUT]
              metadata:
                hearth:
                  intent: nas.workspace.create
                  action: CREATE
                  domain: NAS
                  class: command
                  audience: nas-orchestrator
                  resourceType: WORKSPACE
                  resourceId: "{username}"
                  namespace: OWNED
                  upstreamPath: /internal/nas/files{path}
                  params:
                    path: "{path}"
                    sizeBytes: "header:Content-Length"
                    sha256: "header:X-Checksum-SHA256"

            - id: nas-upload-init
              uri: http://nas-orchestrator:8081
              predicates: [Path=/api/v1/nas/uploads, Method=POST]
              filters:
                - name: ModifyResponseBody
                  args:
                    inClass: java.util.Map
                    outClass: java.util.Map
                    rewriteFunction: "#{@uploadTicketRewrite}"
              metadata:
                hearth:
                  intent: nas.upload.file
                  action: CREATE
                  domain: NAS
                  class: ticket
                  audience: nas-orchestrator
                  resourceType: WORKSPACE
                  resourceId: "{username}"
                  namespace: OWNED
                  upstreamPath: /internal/nas/uploads

            - id: element-control
              uri: http://element-registry:9200
              predicates: [Path=/api/v1/elements/{elementId}/state, Method=PUT]
              metadata:
                hearth:
                  intent: element.device.control
                  action: CONTROL
                  domain: ELEMENT     # ← triggers ELEMENT domain branch in PolicyFilter
                  class: command
                  audience: element-registry
                  resourceType: ELEMENT
                  resourceId: "{elementId}"
                  namespace: OWNED
                  upstreamPath: /internal/elements/{elementId}/state

            - id: auth-login
              uri: http://auth-service:9000
              predicates: [Path=/api/v1/auth/login, Method=POST]
              metadata:
                hearth: { public: true }

  codec:
    max-in-memory-size: 64KB

server:
  port: 8443

management:
  server:
    port: 8081
  endpoints:
    web:
      base-path: /internal
      exposure:
        include: jwks,health

hearth:
  auth:
    jwks-uri: http://auth-service:9000/.well-known/jwks.json
  gateway:
    keys-dir: ${GATEWAY_KEYS_DIR:/run/secrets/gateway-keys}
    current-kid: ${GATEWAY_CURRENT_KID:gw-2026-11}
  policy:
    endpoints:
      NAS: policy-registry:9100
      ELEMENT: policy-registry:9100   # same instance; splitting later = config change only
```

### 4.4 `filter/AuthenticationFilter.java` (JwtVerifier-based, Boot 4)

```java
package com.tamojit.apigateway.filter;

import com.nimbusds.jwt.JWTClaimsSet;
import com.tamojit.apigateway.gateway.*;
import com.tamojit.hearth.common.*;
import org.springframework.cloud.gateway.filter.*;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {
    public static final String SUBJECT_ATTR = "hearth.subject";

    private final JwtVerifier accessVerifier;
    private final ReactiveStringRedisTemplate redis;
    private final AuditPublisher audit;

    public AuthenticationFilter(JwtVerifier accessVerifier, ReactiveStringRedisTemplate redis,
                                AuditPublisher audit) {
        this.accessVerifier = accessVerifier; this.redis = redis; this.audit = audit;
    }

    @Override
    public Mono<Void> filter(org.springframework.web.server.ServerWebExchange ex,
                             GatewayFilterChain chain) {
        RouteMeta meta = RouteMeta.of(ex);
        if (meta == null) return Problems.write(ex, 404, "ROUTE_NOT_FOUND");
        if (meta.publicRoute()) return chain.filter(ex);

        String auth = ex.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (auth == null || !auth.startsWith("Bearer "))
            return audit.authRejected(ex, "AUTH_INVALID")
                        .then(Problems.write(ex, 401, "AUTH_INVALID"));

        return Mono.fromCallable(() -> accessVerifier.verify(auth.substring(7)))
                .onErrorResume(JwtVerifier.Rejected.class, e ->
                        audit.authRejected(ex, "AUTH_INVALID")
                             .then(Mono.error(new RejectRequest(401, "AUTH_INVALID"))))
                .onErrorResume(JwtVerifier.Unavailable.class, e ->
                        Mono.error(new RejectRequest(503, "AUTH_UNAVAILABLE")))
                .flatMap(claims -> checkRevoked(ex, chain, claims))
                .onErrorResume(RejectRequest.class, e ->
                        Problems.write(ex, e.status(), e.code()));
    }

    private Mono<Void> checkRevoked(org.springframework.web.server.ServerWebExchange ex,
                                    GatewayFilterChain chain, JWTClaimsSet c) {
        String sid = c.getClaim("sid") == null ? "" : c.getClaim("sid").toString();
        String jti = c.getJWTID() == null ? "" : c.getJWTID();
        return Mono.zip(redis.hasKey("deny:sid:" + sid), redis.hasKey("deny:jti:" + jti))
                .flatMap(t -> {
                    if (Boolean.TRUE.equals(t.getT1()) || Boolean.TRUE.equals(t.getT2()))
                        return audit.authRejected(ex, "SESSION_REVOKED")
                                    .then(Problems.write(ex, 401, "SESSION_REVOKED"));
                    try {
                        ex.getAttributes().put(SUBJECT_ATTR, new Intent.Subject(
                                c.getSubject(), c.getStringClaim("username"),
                                c.getStringClaim("role"), sid));
                    } catch (Exception e) {
                        return Problems.write(ex, 401, "AUTH_INVALID");
                    }
                    return chain.filter(ex);
                }).onErrorResume(Exception.class, e -> Problems.write(ex, 503, "AUTH_UNAVAILABLE"));
    }

    record RejectRequest(int status, String code) {}
    @Override public int getOrder() { return -250; }
}
```

### 4.5 `gateway/RouteMeta.java`

```java
package com.tamojit.apigateway.gateway;

import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.web.server.ServerWebExchange;
import java.util.Map;

public record RouteMeta(
        String intent, String action, String domain, String clazz,
        String audience, String resourceType, String resourceId,
        String qualifier, String namespace, String upstreamPath,
        boolean publicRoute, boolean skipPolicy,
        Map<String, String> params
) {
    @SuppressWarnings("unchecked")
    public static RouteMeta of(ServerWebExchange ex) {
        Route route = ex.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        if (route == null) return null;
        Object raw = route.getMetadata().get("hearth");
        if (!(raw instanceof Map<?, ?> m)) return null;
        Map<String, Object> h = (Map<String, Object>) m;
        return new RouteMeta(
                s(h,"intent"), s(h,"action"), s(h,"domain"), s(h,"class"),
                s(h,"audience"), s(h,"resourceType"), s(h,"resourceId"),
                s(h,"qualifier"), s(h,"namespace"), s(h,"upstreamPath"),
                Boolean.parseBoolean(s(h,"public")),
                Boolean.parseBoolean(s(h,"skipPolicy")),
                h.containsKey("params") ? (Map<String, String>) h.get("params") : Map.of());
    }
    private static String s(Map<String, Object> m, String k) {
        Object v = m.get(k); return v == null ? null : v.toString();
    }
}
```

### 4.6 `config/GatewayAuthConfig.java`

```java
package com.tamojit.apigateway.config;

import com.tamojit.hearth.common.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import java.net.URL;
import java.time.Duration;

@Configuration
public class GatewayAuthConfig {
    @Value("${hearth.auth.jwks-uri}") private String authJwksUri;

    @Bean
    public JwtVerifier accessTokenVerifier() throws Exception {
        DiskBackedJwkSource src = new DiskBackedJwkSource(new URL(authJwksUri), "hearth-auth");
        return new JwtVerifier(src,
                new JwtVerifier.Spec("at+jwt", "hearth-auth", "hearth-gateway", Duration.ofSeconds(5)));
    }
}
```

### 4.7 `jwks/JwksEndpoint.java`

```java
package com.tamojit.apigateway.jwks;

import com.tamojit.apigateway.config.GatewayKeys;
import org.springframework.boot.actuate.endpoint.annotation.*;
import org.springframework.stereotype.Component;
import java.util.Map;

@Component
@WebEndpoint(id = "jwks")
public class JwksEndpoint {
    private final GatewayKeys keys;
    public JwksEndpoint(GatewayKeys keys) { this.keys = keys; }
    @ReadOperation
    public Map<String, Object> jwks() { return keys.publicJwkSet().toJSONObject(); }
}
```

Domain services reach `http://api-gateway:8081/internal/jwks` for the gateway public keys.

---

## Phase 5: element-registry stub

```
element-registry/src/main/java/com/tamojit/elementregistry/controller/ElementController.java
```

```java
package com.tamojit.elementregistry.controller;

import com.tamojit.hearth.common.Hearth;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/internal/elements")
public class ElementController {

    @GetMapping("/{elementId}")
    public ResponseEntity<Map<String, Object>> get(
            @PathVariable String elementId, HttpServletRequest req) {
        if (req.getHeader(Hearth.CTX_HEADER) == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(Map.of("elementId", elementId,
                "type", "LIGHT", "qualifier", "LIGHT", "stub", true));
    }

    @PutMapping("/{elementId}/state")
    public ResponseEntity<Map<String, Object>> setState(
            @PathVariable String elementId,
            @RequestBody Map<String, Object> body, HttpServletRequest req) {
        if (req.getHeader(Hearth.CTX_HEADER) == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(Map.of("elementId", elementId, "applied", body, "stub", true));
    }
}
```

`application.properties`:
```properties
spring.application.name=element-registry
server.port=9200
hearth.gateway.jwks-uri=http://api-gateway:8081/internal/jwks
```

---

## Phase 6: nas-orchestrator PEP #2

### 6.1 Add to `nas-orchestrator/pom.xml`

```xml
<dependency>
  <groupId>com.tamojit</groupId>
  <artifactId>hearth-auth-common</artifactId>
  <version>1.0.0</version>
</dependency>
<dependency>
  <groupId>com.nimbusds</groupId>
  <artifactId>nimbus-jose-jwt</artifactId>
  <version>9.37.3</version>
</dependency>
<dependency>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
  <version>2.17.2</version>
</dependency>
```

### 6.2 `hearth/NasHearthConfig.java`

```java
package com.tamojit.nasorchestrator.hearth;

import com.tamojit.hearth.common.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import java.net.URL;
import java.time.Duration;

@Configuration
public class NasHearthConfig {
    @Value("${hearth.gateway.jwks-uri:http://api-gateway:8081/internal/jwks}")
    private String gatewayJwksUri;
    @Value("${spring.application.name:nas-orchestrator}")
    private String selfName;

    @Bean
    public JwtVerifier contextTokenVerifier() throws Exception {
        DiskBackedJwkSource src = new DiskBackedJwkSource(new URL(gatewayJwksUri), "hearth-gateway");
        return new JwtVerifier(src,
                new JwtVerifier.Spec(Hearth.TYP_CTX, Hearth.ISS_GATEWAY, selfName, Duration.ofSeconds(5)));
    }
}
```

### 6.3 `hearth/HearthPrincipal.java`

```java
package com.tamojit.nasorchestrator.hearth;

import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Map;

public record HearthPrincipal(
        String type, String userId, String username, String role, String sessionId,
        String intentId, String intentName, String action,
        String resourceType, String resourceId, String qualifier, String namespace, String scope
) {
    public static final String ATTR = "hearth.principal";

    @SuppressWarnings("unchecked")
    public static HearthPrincipal fromContextToken(JWTClaimsSet c) throws Exception {
        Map<String, Object> res = (Map<String, Object>) c.getClaim("res");
        Map<String, Object> dec = (Map<String, Object>) c.getClaim("decision");
        return new HearthPrincipal("USER", c.getSubject(),
                c.getStringClaim("username"), c.getStringClaim("role"), c.getStringClaim("sid"),
                c.getStringClaim("intentId"), c.getStringClaim("name"), c.getStringClaim("action"),
                (String) res.get("type"), (String) res.get("id"), (String) res.get("qualifier"),
                c.getStringClaim("ns"), (String) dec.get("scope"));
    }
}
```

### 6.4 `hearth/ContextTokenFilter.java`

```java
package com.tamojit.nasorchestrator.hearth;

import com.nimbusds.jwt.JWTClaimsSet;
import com.tamojit.hearth.common.*;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Component
public class ContextTokenFilter extends OncePerRequestFilter {
    private final JwtVerifier contextVerifier;
    public ContextTokenFilter(JwtVerifier contextTokenVerifier) { this.contextVerifier = contextTokenVerifier; }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest req) {
        return !req.getRequestURI().startsWith("/internal/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res,
                                    FilterChain chain) throws ServletException, IOException {
        String ctx = req.getHeader(Hearth.CTX_HEADER);
        if (ctx == null) { write(res, 401, "AUTH_INVALID"); return; }
        try {
            JWTClaimsSet claims = contextVerifier.verify(ctx);
            String expectedBind = BindCalculator.bind(
                    req.getMethod(), req.getRequestURI(), req.getQueryString(),
                    req.getHeader("X-Checksum-SHA256"), null);
            String tokenBind = claims.getStringClaim("bind");
            if (tokenBind == null || !MessageDigest.isEqual(
                    expectedBind.getBytes(StandardCharsets.UTF_8),
                    tokenBind.getBytes(StandardCharsets.UTF_8))) {
                write(res, 403, "INTENT_BINDING_MISMATCH"); return;
            }
            req.setAttribute(HearthPrincipal.ATTR, HearthPrincipal.fromContextToken(claims));
            chain.doFilter(req, res);
        } catch (JwtVerifier.Rejected e) { write(res, 401, "AUTH_INVALID");
        } catch (JwtVerifier.Unavailable e) { write(res, 503, "AUTH_UNAVAILABLE");
        } catch (Exception e) { write(res, 401, "AUTH_INVALID"); }
    }

    private void write(HttpServletResponse r, int status, String code) throws IOException {
        r.setStatus(status); r.setContentType("application/problem+json");
        r.getWriter().write("{\"status\":" + status + ",\"code\":\"" + code + "\"}");
    }
}
```

### 6.5 `hearth/WorkspaceAccess.java`

```java
package com.tamojit.nasorchestrator.hearth;

import com.tamojit.hearth.common.ScopeEnforcer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.nio.file.*;

@Component
public class WorkspaceAccess {
    private final Path workspacesRoot;
    public WorkspaceAccess(@Value("${hearth.nas.workspaces-root:/mnt/tank/workspaces}") String root) {
        this.workspacesRoot = Path.of(root);
    }

    public Path resolve(HearthPrincipal p, String relativePath) {
        enforceScope(p);
        Path wsRoot = workspacesRoot.resolve(p.resourceId()).normalize();
        String rel = relativePath.startsWith("/") ? relativePath.substring(1) : relativePath;
        Path target = wsRoot.resolve(rel).normalize();
        if (!target.startsWith(wsRoot) || !wsRoot.startsWith(workspacesRoot))
            throw new ScopeEnforcer.ScopeViolation("PATH_ESCAPE");
        rejectSymlinks(wsRoot, target);
        return target;
    }

    private void enforceScope(HearthPrincipal p) {
        ScopeEnforcer.of(p.scope()).enforce(p.username(), p.resourceId(), p.namespace());
    }

    private void rejectSymlinks(Path root, Path target) {
        Path current = root;
        for (Path segment : root.relativize(target)) {
            current = current.resolve(segment);
            if (Files.isSymbolicLink(current))
                throw new ScopeEnforcer.ScopeViolation("SYMLINK_REJECTED: " + current);
        }
    }
}
```

### 6.6 `controller/InternalNasController.java`

```java
package com.tamojit.nasorchestrator.controller;

import com.tamojit.hearth.common.ScopeEnforcer;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;

import java.util.*;

@RestController
@RequestMapping("/internal/nas")
public class InternalNasController {
    private final WorkspaceAccess workspaceAccess;

    public InternalNasController(WorkspaceAccess workspaceAccess) {
        this.workspaceAccess = workspaceAccess;
    }

    @GetMapping("/files/list")
    public ResponseEntity<?> listFiles(@RequestParam(defaultValue = "") String path, HttpServletRequest req) {
        HearthPrincipal p = principal(req);
        var resolved = workspaceAccess.resolve(p, path);
        // ... call existing FileService with resolved path
        return ResponseEntity.ok(Map.of("path", resolved.toString(), "files", List.of()));
    }

    @GetMapping("/files/**")
    public ResponseEntity<?> readFile(HttpServletRequest req) {
        HearthPrincipal p = principal(req);
        String path = req.getRequestURI().replaceFirst("/internal/nas/files", "");
        var resolved = workspaceAccess.resolve(p, path);
        // ... stream from NAS
        return ResponseEntity.ok().build();
    }

    @PutMapping("/files/**")
    public ResponseEntity<?> createFile(HttpServletRequest req) {
        HearthPrincipal p = principal(req);
        String path = req.getRequestURI().replaceFirst("/internal/nas/files", "");
        var resolved = workspaceAccess.resolve(p, path);
        // ... stream request body to NAS, verify SHA256
        return ResponseEntity.status(201).build();
    }

    @PostMapping("/uploads")
    public ResponseEntity<Map<String, Object>> initUpload(@RequestParam String path, HttpServletRequest req) {
        HearthPrincipal p = principal(req);
        workspaceAccess.resolve(p, path);  // scope + traversal check
        String uploadId = "u-" + UUID.randomUUID().toString().substring(0, 8);
        return ResponseEntity.ok(Map.of("uploadId", uploadId));
    }

    @ExceptionHandler(ScopeEnforcer.ScopeViolation.class)
    public ResponseEntity<?> handleScopeViolation(ScopeEnforcer.ScopeViolation e) {
        return ResponseEntity.status(403)
            .body(Map.of("status", 403, "code", "SCOPE_VIOLATION", "detail", e.getMessage()));
    }

    private HearthPrincipal principal(HttpServletRequest req) {
        HearthPrincipal p = (HearthPrincipal) req.getAttribute(HearthPrincipal.ATTR);
        if (p == null) throw new IllegalStateException("No HearthPrincipal — ContextTokenFilter not applied");
        return p;
    }
}
```

### 6.7 `nas-orchestrator/application.properties` additions

```properties
# Add / replace these lines:
hearth.gateway.jwks-uri=http://api-gateway:8081/internal/jwks
hearth.nas.workspaces-root=/mnt/tank/workspaces

# Remove these old lines:
# auth.grpc.host=...
# auth.grpc.port=...
# auth.jwt.secret=...
```

---

## Phase 7: docker-compose.yml (rewritten)

```yaml
version: '3.8'

networks:
  hearth-internal:
    driver: bridge
    internal: true      # no route off the host
  hearth-edge:
    driver: bridge      # gateway + data-plane only

volumes:
  redis-data:
  postgres-data:

services:

  redis:
    image: redis:7-alpine
    container_name: redis
    command: redis-server --save 60 1 --loglevel warning
    volumes: [redis-data:/data]
    networks: [hearth-internal]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10

  zookeeper:
    image: confluentinc/cp-zookeeper:7.4.0
    container_name: zookeeper
    environment: { ZOOKEEPER_CLIENT_PORT: 2181 }
    networks: [hearth-internal]

  kafka:
    image: confluentinc/cp-kafka:7.4.0
    container_name: kafka
    depends_on: [zookeeper]
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:29092
      KAFKA_INTER_BROKER_LISTENER_NAME: PLAINTEXT
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"
    networks: [hearth-internal]
    healthcheck:
      test: ["CMD", "kafka-broker-api-versions", "--bootstrap-server", "localhost:29092"]
      interval: 10s
      timeout: 10s
      retries: 10
      start_period: 30s

  postgres:
    image: postgres:17-alpine
    container_name: postgres
    build:
      context: .
      dockerfile: ./Dockerfile
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_SUPERUSER_PASSWORD}
      AUTH_DB_PASSWORD: ${AUTH_DB_PASSWORD}
      POLICY_DB_PASSWORD: ${POLICY_DB_PASSWORD}
      STREAMING_DB_PASSWORD: ${STREAMING_DB_PASSWORD}
      HEARTH_OWNER_USERNAME: ${HEARTH_OWNER_USERNAME}
      HEARTH_OWNER_PASSWORD_HASH: ${HEARTH_OWNER_PASSWORD_HASH}
      VIDEO_SVC_SECRET_HASH: ${VIDEO_SVC_SECRET_HASH}
      ENCODING_SVC_SECRET_HASH: ${ENCODING_SVC_SECRET_HASH}
      STREAMING_SVC_SECRET_HASH: ${STREAMING_SVC_SECRET_HASH}
      GATEWAY_SVC_SECRET_HASH: ${GATEWAY_SVC_SECRET_HASH}
    volumes: [postgres-data:/var/lib/postgresql/data]
    networks: [hearth-internal]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 10

  auth-service:
    build: { context: ., dockerfile: auth-service/Dockerfile }
    container_name: auth-service
    env_file: ./auth-service/.env
    depends_on:
      postgres: { condition: service_healthy }
      redis:    { condition: service_healthy }
      kafka:    { condition: service_healthy }
    networks: [hearth-internal]
    # Ports 9000 and 4091 NOT published — internal only

  policy-registry:
    build: { context: ., dockerfile: policy-registry/Dockerfile }
    container_name: policy-registry
    env_file: ./policy-registry/.env
    depends_on:
      postgres: { condition: service_healthy }
      kafka:    { condition: service_healthy }
    networks: [hearth-internal]

  element-registry:
    build: { context: ., dockerfile: element-registry/Dockerfile }
    container_name: element-registry
    env_file: ./element-registry/.env
    depends_on:
      auth-service: { condition: service_started }
    networks: [hearth-internal]

  api-gateway:
    build: { context: ., dockerfile: api-gateway/Dockerfile }
    container_name: api-gateway
    env_file: ./api-gateway/.env
    depends_on:
      auth-service:    { condition: service_started }
      policy-registry: { condition: service_started }
      redis:           { condition: service_healthy }
      kafka:           { condition: service_healthy }
    ports:
      - "8443:8443"    # TLS client-facing
      - "8081:8081"    # management / JWKS — restrict via firewall on real deployments
    networks: [hearth-internal, hearth-edge]

  nas-orchestrator:
    build: { context: ., dockerfile: nas-orchestrator/Dockerfile }
    container_name: nas-orchestrator
    env_file: ./nas-orchestrator/.env
    depends_on:
      api-gateway: { condition: service_started }
      redis:       { condition: service_healthy }
    networks: [hearth-internal]
    # Ports 8081 and 4092 NOT published

  video-service:
    build: { context: ., dockerfile: video-service/Dockerfile }
    container_name: video-service
    env_file: ./video-service/.env
    depends_on:
      kafka:           { condition: service_healthy }
      nas-orchestrator: { condition: service_started }
    networks: [hearth-internal]

  encoding-service:
    build: { context: ., dockerfile: encoding-service/Dockerfile }
    container_name: encoding-service
    env_file: ./encoding-service/.env
    depends_on:
      kafka:        { condition: service_healthy }
      auth-service: { condition: service_started }
    networks: [hearth-internal]

  streaming-service:
    build: { context: ., dockerfile: streaming-service/Dockerfile }
    container_name: streaming-service
    env_file: ./streaming-service/.env
    depends_on:
      redis:           { condition: service_healthy }
      kafka:           { condition: service_healthy }
      nas-orchestrator: { condition: service_started }
      auth-service:    { condition: service_started }
    networks: [hearth-internal]

  notification-service:
    build: { context: ., dockerfile: notification-service/Dockerfile }
    container_name: notification-service
    env_file: ./notification-service/.env
    depends_on:
      kafka: { condition: service_healthy }
    networks: [hearth-internal]
```

---

## Phase 8: Dockerfile template (each service)

```dockerfile
FROM eclipse-temurin:21-jdk AS build
WORKDIR /build

# 1. Install shared library first (required by all services)
COPY hearth-auth-common /hearth-auth-common
RUN mvn -q -f /hearth-auth-common/pom.xml install -DskipTests

# 2. Build the service
COPY <service-name> /<service-name>
RUN mvn -q -f /<service-name>/pom.xml package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /<service-name>/target/*.jar app.jar
EXPOSE <port>
ENTRYPOINT ["java", "-jar", "app.jar"]
```

> Build context **must** be the repo root so both `hearth-auth-common` and the service directory are available.

---

## Phase 9: service client credentials (video, encoding, streaming)

Each service gets a `ServiceTokenRefresher` that calls `POST /oauth/token` on auth-service and caches the JWT. Remove all old `SERVICE` user password-based auth.

```java
package com.tamojit.<service>.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class ServiceTokenRefresher {
    private static final Logger log = LoggerFactory.getLogger(ServiceTokenRefresher.class);

    @Value("${auth.service.url:http://auth-service:9000}") private String authUrl;
    @Value("${auth.client.id}")       private String clientId;
    @Value("${auth.client.secret}")   private String clientSecret;
    @Value("${auth.client.audience}") private String audience;
    @Value("${auth.client.scope}")    private String scope;

    private final AtomicReference<String> currentToken = new AtomicReference<>();
    private volatile Instant refreshAt = Instant.MIN;
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();

    @PostConstruct public void init() { refresh(); }

    @Scheduled(fixedDelay = 10_000)
    public void maybeRefresh() { if (Instant.now().isAfter(refreshAt)) refresh(); }

    private synchronized void refresh() {
        try {
            String body = "grant_type=client_credentials"
                    + "&client_id=" + clientId
                    + "&client_secret=" + clientSecret
                    + "&audience=" + audience
                    + "&scope=" + scope;
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(authUrl + "/oauth/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            JsonNode node = json.readTree(resp.body());
            currentToken.set(node.get("accessToken").asText());
            long expiresIn = node.get("expiresIn").asLong(600);
            refreshAt = Instant.now().plusSeconds(expiresIn - 60);
            log.info("Service token refreshed for {}", clientId);
        } catch (IOException | InterruptedException e) {
            log.error("Service token refresh failed: {}", e.getMessage());
        }
    }

    public String get() {
        String t = currentToken.get();
        if (t == null) throw new IllegalStateException("No service token available yet");
        return t;
    }
}
```

**Add to each service's `.env`:**

```env
# encoding-service/.env
AUTH_SERVICE_URL=http://auth-service:9000
AUTH_CLIENT_ID=encoding-service
AUTH_CLIENT_SECRET=changeme_encoding
AUTH_CLIENT_AUDIENCE=nas-orchestrator
AUTH_CLIENT_SCOPE=nas:read:raw/** nas:write:encoded/**
```

**Add to `application.properties`:**

```properties
auth.service.url=${AUTH_SERVICE_URL:http://auth-service:9000}
auth.client.id=${AUTH_CLIENT_ID}
auth.client.secret=${AUTH_CLIENT_SECRET}
auth.client.audience=${AUTH_CLIENT_AUDIENCE}
auth.client.scope=${AUTH_CLIENT_SCOPE}
```

---

## Conflict points and resolutions summary

| Conflict | Resolution |
|---|---|
| `resource_grants` table | **Dropped completely**. No `resource_grants` table in DB schema; no grant-lookup queries or logic. |
| `policy_scope` ENUM | **Strictly bounded to `OWN`, `SHARED`, `ANY`**. `GRANTED` and `ASSIGNED` are dropped completely from the database ENUM, entities, and enforcers. |
| `ScopeEnforcer` simplicity | Only `OWN`, `SHARED`, and `ANY` are enforced. No `GrantLookup` interface or dummy null arguments needed. |
| `jwtProcessorCustomizer` (Spring Security 6 only) | **Replaced** with `JwtVerifier` from `hearth-auth-common`. No Spring Security filter chain needed in domain services. |
| Gateway starter path (Boot 4) | `spring-cloud-starter-gateway-server-webflux`. Config path: `spring.cloud.gateway.server.webflux.*`. |
| Policy-registry DB in same DB as auth-service | **Separated**: `antar_policy` is its own DB on its own role. No schema-level sharing. No cross-DB FKs anywhere. |
| `rule_name` column missing | **Added**: `rule_name TEXT NOT NULL` to `policy_rules`. Seeded in AAA.BBB.CCC format. Sent as `rule_name` in `DecideRequest`. |
| Old auth-service on port 8085 | Rewritten. Listens on **9000**. gRPC stays on **4091** (legacy, until P7). |
| All service ports published in old compose | Only `api-gateway:8443` and `:8081` published. Everything else `hearth-internal` (no published ports). |
| Old `SERVICE` user accounts | Replaced with `service_clients` table + `/oauth/token` client_credentials grant. `ServiceTokenRefresher` in each domain service. |

---

## Exit checklist per phase

### Phase 0 (hearth-auth-common)
- [ ] `mvn test` passes all bind-vector tests
- [ ] `equivTo` pairs produce identical `bind()` output

### Phase 1 (DB)
- [ ] `SELECT count(*) FROM policy_rules` = 84
- [ ] `SELECT username, role FROM users` shows OWNER row
- [ ] `SELECT client_id FROM service_clients` shows all 4 service principals

### Phase 2 (auth-service)
- [ ] `POST /api/v1/auth/login` returns `{accessToken, refreshToken, expiresIn:900}`
- [ ] Token header: `alg=ES256`, `typ=at+jwt`
- [ ] Token claims: `iss=hearth-auth`, `aud=hearth-gateway`, `username`, `role`, `sid`
- [ ] `GET /.well-known/jwks.json` returns `{"keys":[...]}`
- [ ] Refresh rotation: second refresh with first token fails 401
- [ ] `POST /oauth/token` returns service JWT: `aud=nas-orchestrator`, `sub=svc:encoding-service`

### Phase 3 (policy-registry)
- [ ] `Decide(NAS, RESIDENT, CREATE, WORKSPACE)` → `{ALLOW, OWN}`
- [ ] `Decide(NAS, RESIDENT, DELETE, SHARED)` → `{DENY, NO_MATCHING_RULE}`
- [ ] `Decide(ELEMENT, GUEST, STREAM, ELEMENT, qualifier=CAMERA)` → `{DENY, EXPLICIT_DENY}`
- [ ] `Decide(NAS, OWNER, DELETE, WORKSPACE)` → `{ALLOW, ANY}`

### Phase 4 (api-gateway)
- [ ] Request without `Authorization` → 401 `AUTH_INVALID`
- [ ] Valid token → passes to service with `X-Hearth-Context`
- [ ] Revoked `sid` in Redis → 401 `SESSION_REVOKED`
- [ ] Policy DENY → 403 `POLICY_DENIED`
- [ ] Policy down (503 from registry) → 503 `POLICY_UNAVAILABLE`
- [ ] `GET http://api-gateway:8081/internal/jwks` returns gateway public JWKS

### Phase 5+6 (nas-orchestrator PEP #2)
- [ ] Request to `/internal/nas/files/list` with valid context token → 200
- [ ] Wrong `aud` in context token → 401
- [ ] Altered path in request → 403 `INTENT_BINDING_MISMATCH`
- [ ] RESIDENT accessing another user's workspace → 403 `SCOPE_VIOLATION`
- [ ] ELEMENT route → goes through ELEMENT domain branch in `PolicyFilter`
