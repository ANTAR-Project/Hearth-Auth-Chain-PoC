# HEARTH Auth Chain: Architecture Walkthrough and Implementation Guide

ANTAR · HEARTH · Version 1.0 · 19 November 2026 · Status: design baseline

## 1. Purpose, scope and design rules

This document explains how a request is authenticated, authorized and executed inside HEARTH, and how to implement every part of that chain. All HEARTH services live in one fabric (.10). There is no separate INFRA fabric. Resident, guest and IoT fabrics are outside it and reach HEARTH only through the two published ports in section 2.2.

**In scope:** API gateway, auth-service, policy-registry, domain services (nas-orchestrator, element-orchestrator, element-registry), the NAS data plane, tokens, intents, Redis and Kafka usage, network exposure, testing.

**Deferred:** constraints (quotas, size caps), policy versioning, complex or nested params, ETag and If-Match concurrency, decision signing by policy-registry.

### Design rules

| # | Rule |
| --- | --- |
| R1 | Every client request is authenticated and authorized at the gateway, once, before it can reach a domain service. |
| R2 | The client sends a request, never an intent. The gateway derives the intent from the matched route. |
| R3 | An intent is immutable and exists once per request. Lifecycle state is stored separately. |
| R4 | Domain services never call auth-service or policy-registry per request. They verify signed tokens locally. |
| R5 | Domain services never trust a client-supplied value. A signed value proves only what the gateway saw. |
| R6 | Bulk transfers (large uploads, HLS) use a ticket and the data plane, not the gateway. |
| R7 | Fail closed. If authentication, policy or token verification cannot complete, the request is dropped. |

## 2. Architecture at a glance

### 2.1 Components

| Component | Role | Auth-chain responsibility |
| --- | --- | --- |
| API gateway (Spring Cloud Gateway) | Single client entry, enforcement point 1 (PEP #1) | Verify access JWT, build intent, call Decide, mint context tokens and tickets, idempotency, audit |
| auth-service | Identity provider | Passkeys, sessions, access and refresh tokens, JWKS, client-credentials for services, revocation |
| policy-registry | Decision point (PDP) | `Decide(domain, subject, action, resource)` returns effect and scope. Domains: NAS, ELEMENT |
| element-registry | Element catalogue | Element attributes and capabilities. Verifies context tokens (PEP #2) |
| element-orchestrator | Device commands | Verifies context token, validates capability, executes |
| nas-orchestrator | NAS file operations | Control plane: verifies context token or service JWT. Scope enforcement |
| nas-data-plane | Bulk transfer | Verifies tickets only. No control endpoints |
| Redis | Fast shared state | Idempotency records, denylists, passkey challenges |
| Kafka | Events | `intent.audit`, `session.revoked`, `policy.changed`, `intent.requested`, file and element events |
| Postgres | Persistence | Users, roles, grants, policy rules, sessions |

### 2.2 Network exposure on fabric .10

| Listener | Reachable from | Purpose |
| --- | --- | --- |
| gateway :8443 (TLS) | Client fabrics | All control-plane requests |
| nas-data-plane :8444 (TLS) | Client fabrics | Ticket-only transfers |
| gateway management :8081 | .10 internal only | Gateway JWKS for domain services |
| auth-service :9000 | .10 internal only | JWKS, token endpoint for services |
| policy-registry, registries, orchestrators, Redis, Kafka, Postgres | .10 internal only | Never published to client fabrics |

The firewall between client fabrics and .10 allows exactly two destinations: the HEARTH host on 8443 and 8444. Inside the host, backend services sit on a Docker network declared `internal: true` and publish no ports. Because everything shares .10, the token checks in domain services (section 8) are the real defence against lateral movement.

### 2.3 Credentials and trust anchors

| Credential | `typ` header | Issuer | Verified by | Lifetime | Purpose |
| --- | --- | --- | --- | --- | --- |
| Access JWT | `at+jwt` | auth-service | Gateway (auth JWKS) | 15 min | Client identity |
| Refresh token | opaque | auth-service | auth-service | 7 days, rotating | Obtain new access JWT |
| Context token | `hearth-ctx+jwt` | Gateway | Domain services (gateway JWKS) | 30 s | Proof that an intent was authorized |
| Ticket | `hearth-ticket+jwt` | Gateway | Data plane (gateway JWKS) | Minutes to hours | Scoped bulk transfer |
| Service JWT | `at+jwt` | auth-service | Domain services (auth JWKS) | 10 min | Service-to-service calls |

All tokens are signed with **ES256** (ECDSA P-256). EdDSA is possible but needs extra libraries, while ES256 works out of the box with Spring Security's Nimbus decoders. Every issuer publishes its public keys as a JWKS with a `kid`. Verifiers cache by `kid`, refresh on an unknown `kid` (rate limited), and persist the last known set to disk so services start without auth-service. Rotation uses an overlap window in which both keys are published.

Every verifier checks `typ`, `iss`, `aud` and `exp`. A credential of one type is therefore useless as another: a user access JWT has `aud=hearth-gateway` and is rejected by every domain service.

## 3. Core concepts

**Intent.** A canonical description of one requested action: what, on which resource, by whom. It is built only by the gateway from the route and the verified token. The client never supplies it.

**Policy points.** The gateway is PEP #1 and drops invalid requests early. policy-registry is the PDP and answers allow or deny with a scope. Each domain service is PEP #2: it verifies the signed decision offline and enforces scope against its own data.

**Scope values** (the PDP's output, enforced by the domain service):

| Scope | Meaning | Check at the domain service |
| --- | --- | --- |
| OWN | The resource belongs to the caller | For WORKSPACE: `resource.id == subject.username` |
| GRANTED | The caller was explicitly given access | Lookup in `resource_grants` |
| ASSIGNED | The element or area is assigned to the caller | Lookup in assignments |
| ANY | Unrestricted within the resource type | None |

**Request classes.** Declared per route.

| Class | Idempotency key | Gateway reads body | Example |
| --- | --- | --- | --- |
| query | No | No | `GET /elements/{id}/capabilities` |
| command | Required | Bounded JSON only | `PUT /elements/{id}/state` |
| ticket | Required | Bounded JSON only | `POST /nas/uploads` |

**Intent lifecycle states** (stored in Redis, not in the envelope):

| State | Meaning |
| --- | --- |
| PROCESSING | Accepted and in flight |
| PROCESSED | Executed successfully |
| DENIED | Policy said no |
| DROPPED | Rejected before policy (validation, conflict, policy unavailable) |
| FAILED | Executed but errored |

Unauthenticated requests never get an intent. They emit an `auth.rejected` audit event only.

## 4. Request lifecycle walkthrough

### 4.1 Control-plane path

| Step | Where | What happens | On failure |
| --- | --- | --- | --- |
| 1 | Gateway | Strip every inbound `X-Hearth-*` header and spoofable identity headers | None |
| 2 | Gateway | Match the route and load its metadata (intent name, action, domain, class) | 404 |
| 3 | Gateway | Verify the access JWT locally (signature, `iss`, `aud`, `exp`, `typ`). Check Redis denylists for `sid` and `jti` | 401, no intent, `auth.rejected` |
| 4 | Gateway | Build the intent: subject from claims, resource and params from route and request | 400 or 422, state DROPPED |
| 5 | Gateway | Commands only: claim the idempotency key in Redis (`PROCESSING`) | 409 or 422, or replay |
| 6 | Gateway | Elements only: enrich `resource.attrs` from element-registry (cached) | 404 |
| 7 | Gateway | Call `Decide` for each involved domain in parallel. Deny wins | 403 DENIED, or 503 if unavailable |
| 8 | Gateway | Mint a 30 s context token for the target service and compute `bind` | 500 |
| 9 | Gateway | Remove the user's `Authorization`, add `X-Hearth-Context`, set the upstream path, stream the request | 502 or 504 |
| 10 | Gateway | After the response: update lifecycle state, emit `intent.audit`, add `X-Hearth-Intent-Id` | None |
| 11 | Domain service | Verify context token offline, recompute `bind`, enforce scope, validate params, execute | 401, 403, 422 |

Auth-service and policy-registry are side calls made by the gateway. They are not hops on the request path.

### 4.2 Worked example: upload `/docs/report.pdf` to your own workspace

Client to gateway:

```http
PUT /api/v1/nas/files/docs/report.pdf HTTP/1.1
Authorization: Bearer <access JWT>
Idempotency-Key: c9d1f0a2-3b7e-4c0a-9e51-6a1d2f7b8c10
X-Checksum-SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
Content-Length: 1048576
If-None-Match: *

<file bytes>
```

The gateway verifies the token, builds the intent (`nas.file.create`, action `CREATE`, resource `WORKSPACE:tamojit`, namespace `OWNED`, params `{path, sizeBytes, sha256}`), claims the idempotency key, and calls `Decide`. policy-registry returns `{effect: ALLOW, scope: OWN}`. The gateway mints a context token and forwards:

```http
PUT /internal/nas/files/docs/report.pdf HTTP/1.1
X-Hearth-Context: <context token, aud=nas-orchestrator>
X-Hearth-Intent-Id: 018f3a6e-...
X-Checksum-SHA256: 9f86d081884c7d65...
Content-Length: 1048576

<file bytes, streamed, never buffered>
```

nas-orchestrator verifies the token against the gateway JWKS, recomputes `bind` from the request it actually received, checks `res.id == username` (scope OWN), resolves the path under `/workspaces/tamojit/` with traversal checks, streams to the NAS and verifies the SHA-256. It answers `201 Created` with `Location` and `ETag`, then publishes the outcome to `intent.audit` under the same `intentId`.

### 4.3 Ticket path (large upload and HLS)

The gateway authorizes once, at intent time, and issues a ticket. The bytes then flow directly between client and data plane on :8444.

- **Upload:** `POST /api/v1/nas/uploads {path, sizeBytes, sha256}` is the intent. nas-orchestrator creates an upload session and returns `uploadId`. A gateway response filter mints a ticket (`act=WRITE`, `res=upload:<uploadId>`) and adds it to the response. The client then sends `PATCH /data/uploads/<uploadId>` with `Authorization: Bearer <ticket>`.
- **Playback:** `POST /api/v1/media/videos/{id}/playback-sessions` is the intent (`STREAM`). The gateway returns a manifest URL with the ticket in the path: `/stream/<ticket>/master.m3u8`. Playlists use relative URIs, so segment requests inherit the ticket.
- The data plane verifies the ticket offline, checks that the request matches `act` and `res`, and checks Redis denylists for `jti` and `sid`.

### 4.4 Header contract

| Direction | Header | Notes |
| --- | --- | --- |
| Client to gateway | `Authorization: Bearer <access JWT>` | All non-public routes |
| Client to gateway | `Idempotency-Key` | Required for commands and ticket routes |
| Client to gateway | `X-Checksum-SHA256`, `Content-Length` | Authorization-relevant file metadata goes in headers, never in a streamed body |
| Client to gateway | `X-Device-Id`, `X-Request-Id`, `Range`, `If-None-Match` | Hints and pass-through |
| Gateway strips | Every `X-Hearth-*`, `X-Forwarded-User`, `X-User-Id`, and the user's `Authorization` | Domain services never see the access JWT |
| Gateway to service | `X-Hearth-Context` (gRPC: `x-hearth-context`) | The only authoritative identity and decision |
| Gateway to service | `X-Hearth-Intent-Id`, `traceparent` | Informational and tracing |
| Gateway to service | `Content-Type`, `Content-Length`, `Range`, `X-Checksum-SHA256` | Passed through unchanged |
| Response | `X-Hearth-Intent-Id`, `Location`, `ETag`, `Idempotent-Replayed` | Errors use `application/problem+json` with a stable `code` |

## 5. Data contracts

### 5.1 Access JWT

```json
{
  "iss": "hearth-auth", "aud": "hearth-gateway",
  "sub": "<userId>", "username": "tamojit", "role": "RESIDENT",
  "sid": "<sessionId>", "amr": ["passkey"],
  "iat": 0, "exp": 0, "jti": "<uuid>"
}
```

Header: `{"alg":"ES256","kid":"auth-2026-11","typ":"at+jwt"}`. `username` is unique, immutable and restricted to `[a-z0-9_-]{3,32}`, because it is both an authorization key and a filesystem path component. Usernames are never reused.

### 5.2 Context token

```json
{
  "iss": "hearth-gateway", "aud": "nas-orchestrator",
  "sub": "<userId>", "username": "tamojit", "role": "RESIDENT", "sid": "<sessionId>",
  "iat": 0, "exp": 0, "jti": "<uuid>",
  "intentId": "<uuidv7>", "name": "nas.file.create", "action": "CREATE",
  "res": { "type": "WORKSPACE", "id": "tamojit", "qualifier": null },
  "ns": "OWNED",
  "decision": { "effect": "ALLOW", "scope": "OWN" },
  "bind": "<base64url sha256 of the canonical upstream request>"
}
```

Header `typ` is `hearth-ctx+jwt`. `exp` is `iat + 30 s`. For compound intents add `rel`: an array of related `res` objects.

### 5.3 The `bind` value

`bind` stops "policy checked on X, executed on Y". It is computed over the **upstream** request, meaning the method and path the service will actually receive after the gateway's own path mapping.

```
bind = base64url( SHA-256(
  METHOD \n normalizedPath \n sortedQuery \n lowercase(X-Checksum-SHA256 or "") \n hex(SHA-256(canonicalJson(bodyIfBoundedJson)) or "")
))
```

Streamed bodies are not hashed; the checksum header stands in for them. Bounded JSON bodies (at most 4 KB) are canonicalized with sorted keys. Both gateway and services compute `bind` with the same shared library (`hearth-auth-common`, section 6.2).

### 5.4 Ticket

```json
{
  "iss": "hearth-gateway", "aud": "nas-data",
  "sub": "<userId>", "username": "tamojit", "sid": "<sessionId>",
  "intentId": "<uuidv7>", "act": "WRITE", "res": "upload:u-7c1e",
  "iat": 0, "exp": 0, "jti": "<uuid>"
}
```

`act` is `READ` or `WRITE`. `res` is an upload session (`upload:<id>`) or a path prefix (`stream:movie-001/`). Header `typ` is `hearth-ticket+jwt`.

### 5.5 Service JWT

```json
{
  "iss": "hearth-auth", "aud": "nas-orchestrator",
  "sub": "svc:encoding-service",
  "scope": "nas:read:raw/** nas:write:encoded/**",
  "iat": 0, "exp": 0, "jti": "<uuid>"
}
```

Issued through `POST /oauth/token` with `grant_type=client_credentials`. Authorization of service calls uses these static scopes, not `Decide`.

### 5.6 Intent envelope

```json
{
  "intentId": "018f3a6e-...",
  "idempotencyKey": "c9d1f0a2-...",
  "name": "nas.file.create",
  "action": "CREATE",
  "resource": { "type": "WORKSPACE", "id": "tamojit", "qualifier": null, "attrs": {} },
  "relatedResources": [],
  "namespace": "OWNED",
  "params": { "path": "/docs/report.pdf", "sizeBytes": 1048576, "sha256": "9f86..." },
  "subject": { "userId": "<userId>", "username": "tamojit", "role": "RESIDENT", "sessionId": "<sid>" },
  "issuedAt": "2026-11-19T10:00:00Z",
  "expiresAt": "2026-11-19T10:00:30Z",
  "decision": { "effect": "ALLOW", "scope": "OWN" }
}
```

| Field | Origin |
| --- | --- |
| `intentId` | Gateway (UUIDv7) |
| `idempotencyKey` | Client header |
| `name`, `action`, `resource.type`, `resource.qualifier`, `namespace` | Route metadata |
| `resource.id` | The resource's own ID: path variable, or `subject.username` on "my workspace" routes. Workspace ID equals username |
| `resource.attrs` | Element-registry lookup (ELEMENT only) |
| `params` | URL, query, headers, small bounded JSON body. Opaque to the gateway |
| `subject` | Verified access JWT only |
| `decision` | PDP response |

`namespace` (OWNED or SHARED) is a property of the route. `decision.scope` is the PDP's verdict. They are different things.

### 5.7 Lifecycle record (Redis)

Key `idem:{userId}:{idempotencyKey}`, TTL 24 h:

```json
{ "intentId": "018f3a6e-...", "state": "PROCESSING", "reqHash": "<sha256 of method, upstream path, canonical params>", "status": null, "location": null }
```

Queries have no idempotency key. They still get an `intentId` and an audit event.

### 5.8 Route manifest

The manifest is plain Spring Cloud Gateway route definitions. Each route carries a `hearth` metadata block, readable in global filters through the matched `Route`.

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: nas-file-create
          uri: http://nas-orchestrator:8081
          predicates:
            - Path=/api/v1/nas/files/{*path}
            - Method=PUT
          metadata:
            hearth:
              intent: nas.file.create
              action: CREATE
              domain: NAS
              class: command
              resourceType: WORKSPACE
              resourceId: "{username}"
              namespace: OWNED
              upstreamPath: "/internal/nas/files{path}"
              params:
                path: "{path}"
                sizeBytes: "header:Content-Length"
                sha256: "header:X-Checksum-SHA256"
        - id: auth-passkey-verify
          uri: http://auth-service:9000
          predicates:
            - Path=/api/v1/auth/passkey/**
          metadata:
            hearth:
              public: true
```

Routes with no `hearth` block are rejected with 404, so a forgotten manifest entry never becomes an open route. The default is deny.

### 5.9 Decide contract (gRPC, gateway to policy-registry)

```protobuf
service Policy { rpc Decide(DecideRequest) returns (DecideResponse); }

message DecideRequest {
  string domain = 1;               // NAS | ELEMENT, from route metadata, never from the client
  Subject subject = 2;             // userId, username, role
  string action = 3;               // READ, CREATE, UPDATE, DELETE, CONTROL, STREAM, SHARE
  Resource resource = 4;           // type, id, qualifier, attrs
  string namespace = 5;            // OWNED | SHARED
}
message DecideResponse {
  string effect = 1;               // ALLOW | DENY
  string scope = 2;                // OWN | GRANTED | ASSIGNED | ANY
  string reason_code = 3;
}
```

### 5.10 Error format

All errors use RFC 9457 `application/problem+json`:

```json
{ "type": "about:blank", "title": "Policy denied", "status": 403, "code": "POLICY_DENIED", "intentId": "018f3a6e-...", "traceId": "..." }
```

The full error catalog is in section 12.

## 6. Gateway implementation

### 6.1 Modules and dependencies

| Module | Contents |
| --- | --- |
| `hearth-auth-common` (library) | Constants, `Intent` records, `BindCalculator`, token validators, `Problems` (RFC 9457 writer), `ScopeEnforcer` |
| `api-gateway` | Spring Cloud Gateway (WebFlux), the filters below, key store, JWKS endpoint |

Runtime: Java 21, Spring Boot 3.3 or later, matching Spring Cloud. Dependencies: `spring-cloud-starter-gateway`, `spring-boot-starter-oauth2-resource-server` (for the Nimbus decoders), `nimbus-jose-jwt`, `spring-boot-starter-data-redis-reactive`, `reactor-kafka`, a reactive gRPC stub generator for the `Policy` service, and Jackson.

### 6.2 Shared library

```java
public final class Hearth {
    public static final String CTX_HEADER = "X-Hearth-Context";
    public static final String INTENT_HEADER = "X-Hearth-Intent-Id";
    public static final String TYP_CTX = "hearth-ctx+jwt";
    public static final String TYP_TICKET = "hearth-ticket+jwt";
    public static final String ISS_GATEWAY = "hearth-gateway";
    public static final String ISS_AUTH = "hearth-auth";
    private Hearth() {}
}

public record Intent(String intentId, String idempotencyKey, String name, String action,
                     Resource resource, List<Resource> relatedResources, String namespace,
                     Map<String, Object> params, Subject subject,
                     Instant issuedAt, Instant expiresAt, Decision decision) {
    public record Resource(String type, String id, String qualifier, Map<String, String> attrs) {}
    public record Subject(String userId, String username, String role, String sessionId) {}
    public record Decision(String effect, String scope) {}

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

The envelope is a record, so it is immutable. Enrichment and the decision produce copies.

```java
public final class BindCalculator {
    private static final ObjectMapper CANON = JsonMapper.builder()
        .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS).build();

    /** method, path and query exactly as the upstream service will receive them (encoded). */
    public static String bind(String method, String rawPath, String rawQuery,
                              String checksum, byte[] jsonBody) {
        String body = (jsonBody == null || jsonBody.length == 0)
            ? "" : hex(sha256(canonicalJson(jsonBody)));
        String canonical = String.join("\n", method.toUpperCase(), rawPath, sortedQuery(rawQuery),
            checksum == null ? "" : checksum.toLowerCase(), body);
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
        try { return CANON.writeValueAsBytes(CANON.readValue(raw, Object.class)); }
        catch (IOException e) { throw new IllegalArgumentException("invalid json", e); }
    }
    // sha256(...) and hex(...) are one-line MessageDigest helpers
}
```

Parsing into `Object` yields maps, and `ORDER_MAP_ENTRIES_BY_KEYS` sorts them, so equal JSON always hashes the same. Gateway and services must use this exact class. Add a golden test file of inputs and expected hashes to the library (section 14).

### 6.3 Filter order

All filters are `GlobalFilter`s with negative order. They run before Spring Cloud Gateway's `RouteToRequestUrlFilter` (order 10000), so the upstream path rewrite in 6.10 is in place before the target URL is built.

| Order | Filter | Responsibility |
| --- | --- | --- |
| -300 | `SanitizeHeadersFilter` | Strip `X-Hearth-*` and spoofable identity headers |
| -250 | `AuthenticationFilter` | Verify access JWT, check denylists, set subject |
| -200 | `IntentFilter` | Build the intent, read bounded JSON body |
| -150 | `IdempotencyFilter` | Claim or replay the idempotency key |
| -120 | `EnrichmentFilter` | Element attrs from element-registry (ELEMENT routes) |
| -100 | `PolicyFilter` | `Decide` per domain, deny wins, fail closed |
| -50 | `ForwardFilter` | Mint context token, rewrite upstream, finish state and audit |
| route filter | `ModifyResponseBody` with ticket rewrite | Mint tickets on ticket routes |

### 6.4 Route metadata access

```java
public record RouteMeta(String intent, String action, String domain, String clazz,
                        String audience, String resourceType, String resourceId,
                        String qualifier, String namespace, String upstreamPath,
                        boolean publicRoute, Map<String, String> params) {

    @SuppressWarnings("unchecked")
    public static RouteMeta of(ServerWebExchange ex) {
        Route route = ex.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        if (route == null || !(route.getMetadata().get("hearth") instanceof Map<?, ?> m)) return null;
        Map<String, Object> h = (Map<String, Object>) m;
        return new RouteMeta(s(h, "intent"), s(h, "action"), s(h, "domain"), s(h, "class"),
            s(h, "audience"), s(h, "resourceType"), s(h, "resourceId"), s(h, "qualifier"),
            s(h, "namespace"), s(h, "upstreamPath"), Boolean.parseBoolean(s(h, "public")),
            (Map<String, String>) h.getOrDefault("params", Map.of()));
    }
    private static String s(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? null : v.toString();
    }
}
```

Add `audience: nas-orchestrator` to each route's metadata block from section 5.8. It names the service that must accept the context token.

### 6.5 SanitizeHeadersFilter

```java
@Component
public class SanitizeHeadersFilter implements GlobalFilter, Ordered {
    @Override
    public Mono<Void> filter(ServerWebExchange ex, GatewayFilterChain chain) {
        ServerHttpRequest req = ex.getRequest().mutate().headers(h -> {
            h.keySet().removeIf(k -> k.toLowerCase().startsWith("x-hearth-"));
            h.remove("X-Forwarded-User");
            h.remove("X-User-Id");
        }).build();
        return chain.filter(ex.mutate().request(req).build());
    }
    @Override public int getOrder() { return -300; }
}
```

### 6.6 AuthenticationFilter

```java
@Bean
ReactiveJwtDecoder authDecoder(@Value("${hearth.auth.jwks-uri}") String jwksUri) {
    NimbusReactiveJwtDecoder d = NimbusReactiveJwtDecoder.withJwkSetUri(jwksUri)
        .jwsAlgorithm(SignatureAlgorithm.ES256)
        .jwtProcessorCustomizer(p -> p.setJWSTypeVerifier(
            new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt"))))
        .build();
    d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
        new JwtTimestampValidator(Duration.ofSeconds(5)),
        new JwtIssuerValidator(Hearth.ISS_AUTH),
        new JwtClaimValidator<List<String>>("aud", a -> a != null && a.contains("hearth-gateway")),
        new JwtClaimValidator<String>("username", u -> u != null && !u.isBlank()),
        new JwtClaimValidator<String>("sid", s -> s != null && !s.isBlank())));
    return d;
}
```

`jwtProcessorCustomizer` needs Spring Security 6.x. Verify the method exists in your version. `at+jwt` is the `typ` auth-service sets.

```java
@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {
    static final String SUBJECT_ATTR = "hearth.subject";
    private final ReactiveJwtDecoder authDecoder;
    private final ReactiveStringRedisTemplate redis;
    private final AuditPublisher audit;

    @Override
    public Mono<Void> filter(ServerWebExchange ex, GatewayFilterChain chain) {
        RouteMeta meta = RouteMeta.of(ex);
        if (meta == null) return Problems.write(ex, 404, "ROUTE_NOT_FOUND");
        if (meta.publicRoute()) return chain.filter(ex);

        String auth = ex.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (auth == null || !auth.startsWith("Bearer ")) return reject(ex, "AUTH_INVALID");

        return authDecoder.decode(auth.substring(7))
            .map(Optional::of)
            .onErrorResume(JwtException.class, e -> Mono.just(Optional.<Jwt>empty()))
            .flatMap(opt -> opt.isEmpty()
                ? reject(ex, "AUTH_INVALID")
                : checkRevoked(ex, chain, opt.get()))
            // Redis unavailable: fail closed
            .onErrorResume(DataAccessException.class,
                e -> Problems.write(ex, 503, "AUTH_UNAVAILABLE"));
    }

    private Mono<Void> checkRevoked(ServerWebExchange ex, GatewayFilterChain chain, Jwt jwt) {
        String sid = jwt.getClaimAsString("sid");
        return Mono.zip(redis.hasKey("deny:sid:" + sid), redis.hasKey("deny:jti:" + jwt.getId()))
            .flatMap(t -> {
                if (t.getT1() || t.getT2()) return reject(ex, "SESSION_REVOKED");
                ex.getAttributes().put(SUBJECT_ATTR, new Intent.Subject(
                    jwt.getSubject(), jwt.getClaimAsString("username"),
                    jwt.getClaimAsString("role"), sid));
                return chain.filter(ex);
            });
    }

    private Mono<Void> reject(ServerWebExchange ex, String code) {
        return audit.authRejected(ex, code).then(Problems.write(ex, 401, code));
    }
    @Override public int getOrder() { return -250; }
}
```

A rejected request has no subject, so no intent is created. Only an `auth.rejected` audit event is emitted, carrying the client IP, route and reason.

### 6.7 IntentFilter

The gateway reads a body only for bounded JSON on command and ticket routes. File routes are never read, so uploads stream.

```java
record Cached(byte[] bytes, ServerWebExchange exchange) {}

static Mono<Cached> readBounded(ServerWebExchange ex, int max) {
    return DataBufferUtils.join(ex.getRequest().getBody(), max)
        .map(buf -> {
            byte[] b = new byte[buf.readableByteCount()];
            buf.read(b);
            DataBufferUtils.release(buf);
            return b;
        })
        .defaultIfEmpty(new byte[0])
        .onErrorMap(DataBufferLimitException.class, e -> new PayloadTooLarge())
        .map(bytes -> new Cached(bytes, ex.mutate().request(
            new ServerHttpRequestDecorator(ex.getRequest()) {
                @Override public Flux<DataBuffer> getBody() {
                    return Flux.just(ex.getResponse().bufferFactory().wrap(bytes));
                }
            }).build()));
}
```

```java
@Component
public class IntentFilter implements GlobalFilter, Ordered {
    static final String INTENT_ATTR = "hearth.intent";
    static final String UPSTREAM_PATH_ATTR = "hearth.upstreamPath";
    static final String BODY_ATTR = "hearth.bodyBytes";
    private static final int MAX_JSON_BODY = 4096;

    @Override
    public Mono<Void> filter(ServerWebExchange ex, GatewayFilterChain chain) {
        RouteMeta meta = RouteMeta.of(ex);
        if (meta == null || meta.publicRoute()) return chain.filter(ex);
        Intent.Subject subject = ex.getAttribute(AuthenticationFilter.SUBJECT_ATTR);

        Map<String, String> vars = new HashMap<>(ServerWebExchangeUtils.getUriTemplateVariables(ex));
        vars.put("username", subject.username());
        vars.put("userId", subject.userId());
        try {
            vars.computeIfPresent("path", (k, v) -> PathGuard.clean(v));
        } catch (IllegalArgumentException e) {
            return Problems.write(ex, 400, "VALIDATION_FAILED");
        }

        boolean json = !"query".equals(meta.clazz())
            && MediaType.APPLICATION_JSON.isCompatibleWith(
                ex.getRequest().getHeaders().getContentType());
        Mono<Cached> body = json ? readBounded(ex, MAX_JSON_BODY)
                                 : Mono.just(new Cached(new byte[0], ex));

        return body.flatMap(c -> {
            ServerHttpRequest req = c.exchange().getRequest();
            Map<String, Object> params = new LinkedHashMap<>();
            meta.params().forEach((k, src) ->
                params.put(k, ParamSource.resolve(src, vars, req.getHeaders(), req.getQueryParams())));
            if (c.bytes().length > 0) params.put("body", Json.parse(c.bytes()));   // opaque to the gateway

            Instant now = Instant.now();
            Intent intent = new Intent(UuidV7.next(), req.getHeaders().getFirst("Idempotency-Key"),
                meta.intent(), meta.action(),
                new Intent.Resource(meta.resourceType(), Templates.fill(meta.resourceId(), vars),
                                    meta.qualifier(), Map.of()),
                List.of(), meta.namespace(), params, subject, now, now.plusSeconds(30), null);

            c.exchange().getAttributes().put(INTENT_ATTR, intent);
            c.exchange().getAttributes().put(UPSTREAM_PATH_ATTR, Templates.fillPath(meta.upstreamPath(), vars));
            c.exchange().getAttributes().put(BODY_ATTR, c.bytes());
            return chain.filter(c.exchange());
        }).onErrorResume(PayloadTooLarge.class, e -> Problems.write(ex, 413, "PAYLOAD_TOO_LARGE"))
          .onErrorResume(IllegalArgumentException.class, e -> Problems.write(ex, 422, "VALIDATION_FAILED"));
    }
    @Override public int getOrder() { return -200; }
}
```

- `Templates.fill` replaces `{name}` placeholders and throws `IllegalArgumentException` for an unknown name. `Templates.fillPath` also percent-encodes each path segment. Spring's path variables arrive decoded, and the upstream path and the `bind` value must use the encoded form the service will actually see.
- `ParamSource.resolve` supports `header:Name`, `query:name`, and templates. Numeric fields (`sizeBytes`) are converted by the manifest schema.
- Authorization-relevant values come from the URL or headers. The JSON body is carried as opaque `params.body`.

```java
final class PathGuard {
    static String clean(String p) {
        String d = URLDecoder.decode(p, StandardCharsets.UTF_8);
        if (d.indexOf((char) 0) >= 0 || d.indexOf((char) 92) >= 0       // NUL and backslash
            || d.chars().anyMatch(Character::isISOControl)) throw new IllegalArgumentException();
        for (String seg : d.split("/")) {
            if (seg.equals("..") || seg.equals(".")) throw new IllegalArgumentException();
        }
        return p;
    }
}
```

The gateway rejects obviously bad paths early. The service still normalizes and checks again (section 8.5), because a signed path proves only what the gateway saw.

### 6.8 IdempotencyFilter

```java
@Component
public class IdempotencyFilter implements GlobalFilter, Ordered {
    private static final Duration IN_FLIGHT_TTL = Duration.ofMinutes(2);   // a crashed gateway cannot wedge a key
    private final ReactiveStringRedisTemplate redis;
    private final ObjectMapper json;

    @Override
    public Mono<Void> filter(ServerWebExchange ex, GatewayFilterChain chain) {
        RouteMeta meta = RouteMeta.of(ex);
        Intent intent = ex.getAttribute(IntentFilter.INTENT_ATTR);
        if (meta == null || intent == null || "query".equals(meta.clazz())) return chain.filter(ex);
        if (intent.idempotencyKey() == null) return Problems.write(ex, 400, "IDEMPOTENCY_KEY_REQUIRED");

        String key = "idem:" + intent.subject().userId() + ":" + intent.idempotencyKey();
        String reqHash = Hashes.requestHash(ex.getRequest().getMethod().name(),
            ex.getAttribute(IntentFilter.UPSTREAM_PATH_ATTR), intent.params());
        ex.getAttributes().put("hearth.idemKey", key);

        return redis.opsForValue()
            .setIfAbsent(key, write(IdemRecord.processing(intent.intentId(), reqHash)), IN_FLIGHT_TTL)
            .flatMap(claimed -> claimed ? chain.filter(ex) : existing(ex, chain, key, reqHash, intent));
    }

    private Mono<Void> existing(ServerWebExchange ex, GatewayFilterChain chain,
                                String key, String reqHash, Intent intent) {
        return redis.opsForValue().get(key).map(this::read).flatMap(rec -> {
            if (!rec.reqHash().equals(reqHash)) return Problems.write(ex, 422, "IDEMPOTENCY_KEY_REUSED");
            return switch (rec.state()) {
                case "PROCESSING" -> Problems.write(ex, 409, "IDEMPOTENCY_IN_FLIGHT");
                case "PROCESSED" -> Replay.write(ex, rec);   // stored status and Location, Idempotent-Replayed: true
                case "DENIED" -> Problems.write(ex, 403, "POLICY_DENIED");
                default -> redis.opsForValue()               // FAILED or DROPPED: retry allowed
                    .set(key, write(IdemRecord.processing(intent.intentId(), reqHash)), IN_FLIGHT_TTL)
                    .then(chain.filter(ex));
            };
        });
    }
    @Override public int getOrder() { return -150; }
}
```

The retry branch should use a Lua compare-and-set on the state, so two simultaneous retries of a failed key cannot both proceed. On completion, `ForwardFilter` rewrites the record with a 24 h TTL.

### 6.9 PolicyFilter

```java
@Component
public class PolicyFilter implements GlobalFilter, Ordered {
    private final PolicyClient policy;          // Mono-based wrapper over the gRPC stub
    private final IntentStateStore states;

    @Override
    public Mono<Void> filter(ServerWebExchange ex, GatewayFilterChain chain) {
        RouteMeta meta = RouteMeta.of(ex);
        Intent intent = ex.getAttribute(IntentFilter.INTENT_ATTR);
        if (meta == null || intent == null) return chain.filter(ex);

        List<Mono<Intent.Decision>> calls = new ArrayList<>();
        calls.add(policy.decide(meta.domain(), intent, intent.resource()));
        for (Intent.Resource r : intent.relatedResources()) {
            calls.add(policy.decide(Domains.of(r.type()), intent, r));
        }

        return Mono.zip(calls, arr -> Arrays.stream(arr).map(Intent.Decision.class::cast).toList())
            .timeout(Duration.ofMillis(800))
            .onErrorMap(t -> new PolicyUnavailable(t))
            .map(PolicyFilter::combine)
            .flatMap(d -> {
                if (!"ALLOW".equals(d.effect())) {
                    return states.mark(ex, "DENIED").then(Problems.write(ex, 403, "POLICY_DENIED"));
                }
                ex.getAttributes().put(IntentFilter.INTENT_ATTR, intent.withDecision(d));
                return chain.filter(ex);
            })
            .onErrorResume(PolicyUnavailable.class, e ->
                states.mark(ex, "DROPPED").then(Problems.write(ex, 503, "POLICY_UNAVAILABLE")));
    }

    /** Deny wins. The scope comes from the primary resource (index 0). */
    static Intent.Decision combine(List<Intent.Decision> ds) {
        boolean denied = ds.stream().anyMatch(d -> !"ALLOW".equals(d.effect()));
        return denied ? new Intent.Decision("DENY", null) : ds.get(0);
    }
    @Override public int getOrder() { return -100; }
}
```

`Mono.zip` runs the calls in parallel and preserves order. `Domains.of` maps WORKSPACE and MEDIA to NAS, and ELEMENT and AREA to ELEMENT. The endpoint per domain comes from configuration (section 9.4), so the `PolicyClient` is the only place that knows whether there are one or two registries.

### 6.10 Context token minting and forwarding

```java
@Component
public class ContextTokenMinter {
    private final GatewayKeys keys;

    public String mint(Intent i, String audience, String bind) {
        Instant now = Instant.now();
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("type", i.resource().type());
        res.put("id", i.resource().id());
        if (i.resource().qualifier() != null) res.put("qualifier", i.resource().qualifier());

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer(Hearth.ISS_GATEWAY).audience(audience)
            .subject(i.subject().userId())
            .claim("username", i.subject().username())
            .claim("role", i.subject().role())
            .claim("sid", i.subject().sessionId())
            .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(30)))
            .jwtID(UUID.randomUUID().toString())
            .claim("intentId", i.intentId()).claim("name", i.name()).claim("action", i.action())
            .claim("res", res).claim("ns", i.namespace())
            .claim("decision", Map.of("effect", i.decision().effect(), "scope", i.decision().scope()))
            .claim("bind", bind)
            .build();
        try {
            ECKey key = keys.current();
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(key.getKeyID()).type(new JOSEObjectType(Hearth.TYP_CTX)).build(), claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("context token signing failed", e);
        }
    }
}
```

```java
@Component
public class ForwardFilter implements GlobalFilter, Ordered {
    private final ContextTokenMinter minter;
    private final IntentStateStore states;
    private final AuditPublisher audit;

    @Override
    public Mono<Void> filter(ServerWebExchange ex, GatewayFilterChain chain) {
        RouteMeta meta = RouteMeta.of(ex);
        Intent intent = ex.getAttribute(IntentFilter.INTENT_ATTR);
        if (meta == null || intent == null) return chain.filter(ex);

        ServerHttpRequest in = ex.getRequest();
        String upstreamPath = ex.getAttribute(IntentFilter.UPSTREAM_PATH_ATTR);
        byte[] jsonBody = ex.getAttribute(IntentFilter.BODY_ATTR);
        String bind = BindCalculator.bind(in.getMethod().name(), upstreamPath,
            in.getURI().getRawQuery(), in.getHeaders().getFirst("X-Checksum-SHA256"), jsonBody);
        String token = minter.mint(intent, meta.audience(), bind);

        ServerHttpRequest out = in.mutate()
            .path(upstreamPath)
            .headers(h -> {
                h.remove(HttpHeaders.AUTHORIZATION);          // services never see the access JWT
                h.set(Hearth.CTX_HEADER, token);
                h.set(Hearth.INTENT_HEADER, intent.intentId());
            }).build();
        ex.getResponse().getHeaders().set(Hearth.INTENT_HEADER, intent.intentId());

        return chain.filter(ex.mutate().request(out).build())
            .then(Mono.defer(() -> finish(ex, intent)));
    }

    private Mono<Void> finish(ServerWebExchange ex, Intent intent) {
        HttpStatusCode status = ex.getResponse().getStatusCode();
        String state = status != null && status.is2xxSuccessful() ? "PROCESSED" : "FAILED";
        return states.complete(ex, intent, state, status)          // 24 h TTL, stores status and Location
            .then(audit.intent(intent, state, status));            // Kafka intent.audit, key = intentId
    }
    @Override public int getOrder() { return -50; }
}
```

The `bind` is computed after the path rewrite, over the encoded path and the raw query string. A mismatch in encoding between gateway and service is the most likely cause of `INTENT_BINDING_MISMATCH` during development, so cover it with the golden vectors.

### 6.11 Ticket minting for upload and playback

Ticket routes forward the intent to the orchestrator like any command. A response rewrite then adds the ticket, so the orchestrator never needs a signing key.

```yaml
- id: nas-upload-init
  uri: http://nas-orchestrator:8081
  predicates: [ "Path=/api/v1/nas/uploads", "Method=POST" ]
  filters:
    - name: ModifyResponseBody
      args:
        inClass: java.util.Map
        outClass: java.util.Map
        rewriteFunction: "#{@uploadTicketRewrite}"
  metadata:
    hearth: { intent: nas.upload.init, action: CREATE, domain: NAS, class: ticket,
              audience: nas-orchestrator, resourceType: WORKSPACE, resourceId: "{username}",
              namespace: OWNED, upstreamPath: "/internal/nas/uploads" }
```

```java
@Bean
RewriteFunction<Map, Map> uploadTicketRewrite(TicketMinter tickets) {
    return (ex, body) -> {
        Intent i = ex.getAttribute(IntentFilter.INTENT_ATTR);
        HttpStatusCode st = ex.getResponse().getStatusCode();
        if (i == null || body == null || body.get("uploadId") == null
                || st == null || !st.is2xxSuccessful()) return Mono.justOrEmpty(body);
        String uploadId = body.get("uploadId").toString();
        Instant exp = Instant.now().plus(Duration.ofMinutes(15));
        Map<String, Object> out = new LinkedHashMap<>(body);
        out.put("intentId", i.intentId());
        out.put("ticket", tickets.mint(i, "nas-data", "WRITE", "upload:" + uploadId, exp));
        out.put("uploadUrl", "https://hearth.local:8444/data/uploads/" + uploadId);
        out.put("expiresAt", exp.toString());
        return Mono.just(out);
    };
}
```

The playback route follows the same pattern. Its rewrite mints `act=READ`, `res=stream:<mediaId>/` with a TTL of the video duration plus margin, and sets `manifestUrl` to `https://hearth.local:8444/stream/<ticket>/master.m3u8`. `TicketMinter` signs with the same gateway key, `typ=hearth-ticket+jwt`, `aud=nas-data`, and the claims in section 5.4.

### 6.12 Gateway keys and JWKS endpoint

```java
@Component
@WebEndpoint(id = "jwks")
public class JwksEndpoint {
    private final GatewayKeys keys;
    @ReadOperation
    public Map<String, Object> jwks() { return keys.publicJwkSet().toJSONObject(); }
}
```

```yaml
management:
  server.port: 8081                       # not published to client fabrics
  endpoints.web:
    base-path: /internal
    exposure.include: jwks
```

Domain services fetch `http://api-gateway:8081/internal/jwks`. `GatewayKeys` holds the current signing key and the previous keys. Rotate every 30 days. Publish both keys until the longest-lived token signed by the old key has expired (the maximum ticket TTL, 6 h), then drop it. Keep the private key in a Docker secret file with mode 0400, never in an environment variable.

### 6.13 Streaming configuration

```yaml
spring:
  cloud:
    gateway:
      httpclient:
        connect-timeout: 2000
        # no response-timeout: long downloads must not be cut off
  codec:
    max-in-memory-size: 64KB            # nothing in the gateway may buffer more than this
server:
  netty:
    max-initial-line-length: 8192
  ssl:
    enabled: true                       # certificate from the local CA
```

Rules for file routes: no `ModifyRequestBody`, no `cacheRequestBody`, no filter that touches the request body. `Range` and `Content-Length` pass through unchanged, and `206 Partial Content` passes back. Verify during testing that gateway heap stays flat during a 1 GB upload.

## 7. auth-service implementation

### 7.1 Endpoints

| Endpoint | Access | Purpose |
| --- | --- | --- |
| `POST /auth/passkey/options` | Public (via gateway) | Issue a WebAuthn challenge, stored in Redis for 2 min |
| `POST /auth/passkey/verify` | Public (via gateway) | Verify the assertion, create a session, return access and refresh tokens |
| `POST /auth/refresh` | Public (via gateway) | Rotate the refresh token, return a new pair |
| `POST /auth/logout` | Bearer, no `Decide` | Revoke the caller's own session |
| `GET /.well-known/jwks.json` | .10 internal | Public keys. `Cache-Control: public, max-age=300` |
| `POST /oauth/token` | .10 internal | Client-credentials grant for services |

`logout` is a self-service route: it is authenticated by the gateway but its manifest entry declares `policy: none`, so the gateway skips `Decide`.

### 7.2 Access token issuing

```java
public String issueAccess(User u, String sid) {
    Instant now = Instant.now();
    JWTClaimsSet c = new JWTClaimsSet.Builder()
        .issuer(Hearth.ISS_AUTH).audience("hearth-gateway")
        .subject(u.id().toString())
        .claim("username", u.username()).claim("role", u.role().name())
        .claim("sid", sid).claim("amr", List.of("passkey"))
        .issueTime(Date.from(now))
        .expirationTime(Date.from(now.plus(Duration.ofMinutes(15))))
        .jwtID(UUID.randomUUID().toString())
        .build();
    return sign(c, "at+jwt");        // ES256, kid of the current auth key
}
```

### 7.3 Passkey login

Use a maintained WebAuthn library (Yubico `java-webauthn-server` or `webauthn4j`). Relying party ID is the HEARTH hostname (for example `hearth.local`). WebAuthn only works in a secure context, so the gateway needs a certificate from your local CA that client devices trust. Store the credential ID, public key and signature counter per user. Require user verification, and reject an assertion whose counter does not advance.

### 7.4 Sessions and refresh rotation

| Table | Columns |
| --- | --- |
| `sessions` | `sid`, `user_id`, `device_id`, `created_at`, `revoked_at`, `revoke_reason` |
| `refresh_tokens` | `token_hash` (SHA-256 of a 256-bit random value), `sid`, `family_id`, `issued_at`, `used_at`, `expires_at` |

The refresh token is opaque and stored only as a hash. Rotation is atomic:

```sql
UPDATE refresh_tokens SET used_at = now()
 WHERE token_hash = :hash AND used_at IS NULL AND expires_at > now()
RETURNING sid, family_id;
```

One row: issue a new access token and a new refresh token in the same family. Zero rows: look the hash up. If it exists with `used_at` set, an old token was replayed, so revoke the whole session. Otherwise return 401.

### 7.5 Revocation

```java
public Mono<Void> revokeSession(String sid, String reason) {
    return redis.opsForValue().set("deny:sid:" + sid, reason, Duration.ofHours(7))
        .then(sessions.markRevoked(sid, reason))
        .then(kafka.send("session.revoked", sid, new SessionRevoked(sid, reason, Instant.now())));
}
```

Redis is written first, so the gateway rejects the session immediately. The denylist TTL covers the longest ticket lifetime (6 h) plus margin, because the data plane checks `deny:sid` on tickets. Revocation triggers: logout, admin action, refresh-token reuse, password-equivalent credential removal.

### 7.6 Role changes

The role claim lives in the access JWT, so a demotion takes up to 15 minutes to show up. To apply it immediately, revoke all of the user's sessions when a role changes. The client's next refresh fails, the user logs in again, and the new token carries the new role.

### 7.7 Service credentials

| Table | Columns |
| --- | --- |
| `service_clients` | `client_id`, `secret_hash` (Argon2), `allowed_audiences`, `allowed_scopes`, `enabled` |

`POST /oauth/token` with `grant_type=client_credentials`, `client_id`, `client_secret`, `audience` and requested `scope`. The audience must be in `allowed_audiences`, and the scope must be a subset of `allowed_scopes`. It returns a 10-minute service JWT (section 5.5). Services cache the token until 60 seconds before expiry. Secrets come from Docker secrets. A later upgrade is `private_key_jwt`, so no shared secret is stored at all.

## 8. Domain service implementation (PEP #2)

Every domain service, before doing any work:

1. Check the credential type: `typ`, `iss`, `aud`.
2. Verify the signature through the cached JWKS, then `exp`.
3. Recompute `bind` from the request actually received and compare.
4. Enforce `decision.scope` against the service's own data.
5. Treat every client-supplied value (`path`, params) as untrusted and normalize it.
6. Emit the outcome under the same `intentId`.

No network call to auth-service or policy-registry happens in this chain. Everything is local verification.

### 8.1 Context token decoder (servlet services)

```java
@Bean
JwtDecoder contextDecoder(@Value("${hearth.gateway.jwks-uri}") String uri,
                          @Value("${spring.application.name}") String self) {
    NimbusJwtDecoder d = NimbusJwtDecoder.withJwkSetUri(uri)
        .jwsAlgorithm(SignatureAlgorithm.ES256)
        .jwtProcessorCustomizer(p -> p.setJWSTypeVerifier(
            new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(Hearth.TYP_CTX))))
        .build();
    d.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
        new JwtTimestampValidator(Duration.ofSeconds(5)),
        new JwtIssuerValidator(Hearth.ISS_GATEWAY),
        new JwtClaimValidator<List<String>>("aud", a -> a != null && a.contains(self))));
    return d;
}
```

`self` is the service's own name, so a token minted for `element-orchestrator` is rejected by `nas-orchestrator`.

### 8.2 The principal

```java
public record HearthPrincipal(String type, String userId, String username, String role,
        String sessionId, String intentId, String action, String resourceType,
        String resourceId, String qualifier, String namespace, String scope,
        List<String> serviceScopes) {

    public static final String ATTR = "hearth.principal";

    static HearthPrincipal fromContext(Jwt jwt) {
        Map<String, Object> res = jwt.getClaim("res");
        Map<String, Object> dec = jwt.getClaim("decision");
        return new HearthPrincipal("USER", jwt.getSubject(), jwt.getClaimAsString("username"),
            jwt.getClaimAsString("role"), jwt.getClaimAsString("sid"), jwt.getClaimAsString("intentId"),
            jwt.getClaimAsString("action"), (String) res.get("type"), (String) res.get("id"),
            (String) res.get("qualifier"), jwt.getClaimAsString("ns"), (String) dec.get("scope"),
            List.of());
    }
}
```

### 8.3 ContextTokenFilter

```java
public class ContextTokenFilter extends OncePerRequestFilter {
    private final JwtDecoder contextDecoder;
    private final ServiceJwtVerifier serviceJwt;     // null on services with no internal callers
    private final SecurityAlerts alerts;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        HttpServletRequest request = BoundedBodyRequest.wrapIfJson(req, 4096);
        String ctx = request.getHeader(Hearth.CTX_HEADER);
        try {
            if (ctx != null) {
                Jwt jwt = contextDecoder.decode(ctx);
                String expected = BindCalculator.bind(request.getMethod(), request.getRequestURI(),
                    request.getQueryString(), request.getHeader("X-Checksum-SHA256"),
                    BoundedBodyRequest.bytes(request));
                String actual = jwt.getClaimAsString("bind");
                if (actual == null || !MessageDigest.isEqual(
                        expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8))) {
                    alerts.raise("INTENT_BINDING_MISMATCH", request, jwt);
                    Problems.write(res, 403, "INTENT_BINDING_MISMATCH");
                    return;
                }
                request.setAttribute(HearthPrincipal.ATTR, HearthPrincipal.fromContext(jwt));
            } else if (serviceJwt != null && request.getHeader(HttpHeaders.AUTHORIZATION) != null) {
                request.setAttribute(HearthPrincipal.ATTR, serviceJwt.verify(request));
            } else {
                alerts.raise("MISSING_CREDENTIAL", request, null);
                Problems.write(res, 401, "AUTH_INVALID");
                return;
            }
        } catch (JwtException e) {
            alerts.raise("INVALID_TOKEN", request, null);
            Problems.write(res, 401, "AUTH_INVALID");
            return;
        }
        chain.doFilter(request, res);
    }
}
```

- `getRequestURI()` returns the encoded path and `getQueryString()` the raw query, which is the form the gateway hashed.
- `BoundedBodyRequest` buffers at most 4 KB and only for `application/json`. Streamed bodies (file uploads) are never buffered here. The checksum header stands in for them.
- Any token failure or `bind` mismatch means someone reached the service without going through the gateway, or a bug exists. Both deserve an alert, not just a 4xx.
- Optional hardening: record `jti` with `SET NX` and a 30 s TTL to reject exact replays.

### 8.4 Scope enforcement and path resolution (nas-orchestrator)

```java
@Component
public class WorkspaceAccess {
    private final GrantRepository grants;
    private final Path workspacesRoot;       // for example /mnt/tank/workspaces

    public Path resolve(HearthPrincipal p, String relativePath) {
        authorize(p);
        Path root = workspacesRoot.resolve(p.resourceId()).normalize();     // workspace id equals username
        String rel = relativePath.startsWith("/") ? relativePath.substring(1) : relativePath;
        Path target = root.resolve(rel).normalize();
        if (!target.startsWith(root) || !root.startsWith(workspacesRoot)) {
            throw new ScopeViolation("PATH_ESCAPE");
        }
        rejectSymlinks(root, target);
        return target;
    }

    private void authorize(HearthPrincipal p) {
        switch (p.scope()) {
            case "OWN" -> {
                if (!p.resourceId().equals(p.username())) throw new ScopeViolation("NOT_OWNER");
            }
            case "GRANTED" -> {
                if (!grants.exists(p.userId(), p.resourceType(), p.resourceId(), p.action()))
                    throw new ScopeViolation("NO_GRANT");
            }
            case "ANY" -> { }
            default -> throw new ScopeViolation("SCOPE_UNSUPPORTED");
        }
    }
}
```

- `OWN` means the workspace is the caller's own: `resource.id == subject.username`. The check uses the values from the verified token, not anything in the request.
- `GRANTED` on a shared file uses the file's ID from the token and looks it up in `resource_grants`. The path comes from the database, not from the request.
- `rejectSymlinks` walks existing components of `target` below `root` and refuses links. If the NAS is reached over the TrueNAS API, the same normalization applies before the call.
- `ScopeViolation` maps to `403 SCOPE_VIOLATION`.

### 8.5 Service JWT verification (internal callers)

```java
public HearthPrincipal verify(HttpServletRequest req) {
    String h = req.getHeader(HttpHeaders.AUTHORIZATION);
    if (h == null || !h.startsWith("Bearer ")) throw new BadJwtException("missing");
    Jwt jwt = serviceDecoder.decode(h.substring(7));   // auth JWKS, typ at+jwt, aud = this service
    if (jwt.getSubject() == null || !jwt.getSubject().startsWith("svc:")) {
        throw new BadJwtException("not a service token");
    }
    List<String> scopes = Arrays.asList(jwt.getClaimAsString("scope").split(" "));
    return new HearthPrincipal("SERVICE", jwt.getSubject(), null, null, null, null, null,
        null, null, null, null, null, scopes);
}

public boolean allows(HearthPrincipal p, String verb, String normalizedRelativePath) {
    return p.serviceScopes().stream().anyMatch(s -> {
        String[] parts = s.split(":", 3);            // nas:read:raw/**
        return parts.length == 3
            && (parts[0] + ":" + parts[1]).equals(verb)
            && matcher.match(parts[2], normalizedRelativePath);
    });
}
```

Service JWTs reach only the internal control port and never carry a user. A user's access JWT fails here because its `aud` is `hearth-gateway`.

### 8.6 Data plane ticket verification (`nas-data-plane`)

Run the data plane as its own deployable on :8444, so the control endpoints do not exist on that port at all.

```java
public class TicketFilter extends OncePerRequestFilter {
    private final JwtDecoder ticketDecoder;   // gateway JWKS, typ hearth-ticket+jwt, aud nas-data
    private final StringRedisTemplate redis;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        try {
            String path = req.getRequestURI();
            String token = path.startsWith("/stream/") ? path.split("/", 4)[2] : bearer(req);
            Jwt t = ticketDecoder.decode(token);
            if (Boolean.TRUE.equals(redis.hasKey("deny:sid:" + t.getClaimAsString("sid")))
                || Boolean.TRUE.equals(redis.hasKey("deny:jti:" + t.getId()))) {
                Problems.write(res, 401, "TICKET_INVALID");
                return;
            }
            if (!matches(t, req)) {
                Problems.write(res, 403, "TICKET_SCOPE_MISMATCH");
                return;
            }
            req.setAttribute("hearth.ticket", t);
            chain.doFilter(req, res);
        } catch (JwtException | IllegalArgumentException e) {
            Problems.write(res, 401, "TICKET_INVALID");
        }
    }

    private boolean matches(Jwt t, HttpServletRequest req) {
        String act = t.getClaimAsString("act");
        String res = t.getClaimAsString("res");
        String m = req.getMethod();
        boolean read = m.equals("GET") || m.equals("HEAD");
        String path = req.getRequestURI();
        if (res.startsWith("upload:")) {                       // tus: HEAD, PATCH, DELETE
            return act.equals("WRITE") && path.equals("/data/uploads/" + res.substring(7));
        }
        if (res.startsWith("stream:")) {                       // /stream/{ticket}/{relative path}
            String[] seg = path.split("/", 4);
            String rest = seg.length > 3 ? seg[3] : "";
            return read && act.equals("READ") && Paths.resolveUnder(res.substring(7), rest) != null;
        }
        return false;
    }
}
```

- `Paths.resolveUnder(prefix, rest)` normalizes and returns null if the result leaves the prefix. The same helper picks the file to serve.
- Per-segment verification is a signature check and two Redis lookups, so it stays cheap. Cache the lookups for a few seconds if segment rates demand it.
- On the final upload chunk the data plane verifies the SHA-256, then writes `deny:jti:{jti}` so the ticket cannot create a second file.
- Keep `/stream/<ticket>/...` paths out of access logs and referrer headers.

### 8.7 element-registry and element-orchestrator

Both use the same `ContextTokenFilter` from the shared library. Beyond that:

- **element-registry** answers capability and attribute reads. It also serves the gateway's enrichment lookups, authenticated with a service JWT (`aud=element-registry`, scope `elements:read`). It publishes `element.changed` so the gateway evicts cached attributes.
- **element-orchestrator** enforces `ASSIGNED` against `element_assignments` (user to element or area). It then fetches capabilities from element-registry, again with a service JWT, and validates params against them (`422 CAPABILITY_UNSUPPORTED` on mismatch). It takes a per-element lock, sends the command through the device adapter, waits for the ack and publishes `element.state.changed`.
- Vendor params stay opaque to the gateway. Capability validation is the orchestrator's job, not policy's.

### 8.8 gRPC variant

If the gateway talks gRPC to a service, carry the token in metadata `x-hearth-context`, and verify it in a `ServerInterceptor` using the same decoder. Canonicalize the request for `bind` as follows:

| `bind` input | gRPC value |
| --- | --- |
| METHOD | `GRPC` |
| path | `/<fullMethodName>/<resourceId>`, for example `/hearth.element.v1.Element/SetState/<elementId>` |
| query | empty |
| checksum | empty |
| body | canonical JSON of the request message params |

The gateway and the interceptor must both compute it from the typed message, not from serialized bytes.

## 9. policy-registry implementation

### 9.1 Rule model

`policy_rules(id, domain, role, action, resource_type, qualifier NULL, namespace NULL, effect, scope, enabled)`

| Domain | Role | Action | Resource type | Qualifier | Namespace | Effect | Scope |
| --- | --- | --- | --- | --- | --- | --- | --- |
| NAS | RESIDENT | CREATE | WORKSPACE | any | OWNED | ALLOW | OWN |
| NAS | RESIDENT | READ | WORKSPACE | any | OWNED | ALLOW | OWN |
| NAS | RESIDENT | READ | WORKSPACE | any | SHARED | ALLOW | GRANTED |
| NAS | RESIDENT | STREAM | MEDIA | any | any | ALLOW | ANY |
| NAS | GUEST | any | WORKSPACE | any | any | DENY | none |
| ELEMENT | RESIDENT | CONTROL | ELEMENT | LIGHT | any | ALLOW | ANY |
| ELEMENT | GUEST | CONTROL | ELEMENT | LIGHT | any | ALLOW | ASSIGNED |
| ELEMENT | GUEST | CONTROL | ELEMENT | CAMERA | any | DENY | none |

### 9.2 Decision algorithm

```java
public Decision decide(DecideRequest r) {
    List<Rule> matching = rules.forDomain(r.getDomain()).stream()
        .filter(x -> x.role().equals(r.getSubject().getRole()))
        .filter(x -> x.action().equals("*") || x.action().equals(r.getAction()))
        .filter(x -> x.resourceType().equals(r.getResource().getType()))
        .filter(x -> x.qualifier() == null || x.qualifier().equals(r.getResource().getQualifier()))
        .filter(x -> x.namespace() == null || x.namespace().equals(r.getNamespace()))
        .toList();

    return matching.stream()
        .max(Comparator.comparingInt(Rule::specificity)               // non-wildcard fields count
                       .thenComparing(x -> x.effect().equals("DENY"))) // DENY beats ALLOW at equal specificity
        .map(x -> new Decision(x.effect(), x.effect().equals("ALLOW") ? x.scope() : null, x.reason()))
        .orElse(Decision.deny("NO_RULE"));                             // default deny
}
```

`Rule.specificity()` counts the non-wildcard fields among action, qualifier and namespace.

### 9.3 Performance and cache

Rules are loaded into memory at startup and reloaded when a `policy.changed` event arrives. `Decide` is then a pure in-memory function with no database call per request.

### 9.4 One registry now, two later

Run one deployable with two logical domains. The `domain` in the request selects the rule partition. The gateway maps each domain to an endpoint, so splitting into two registries later is a configuration change with no code change:

```yaml
hearth:
  policy:
    endpoints:
      NAS: policy-registry:9090
      ELEMENT: policy-registry:9090      # later: element-policy-registry:9090
```

### 9.5 Administration

Rules are changed through an admin API restricted to the Owner role, written to Postgres, and followed by `policy.changed {domain}`. Every change is audited. Decisions are not cached by the gateway, so a change takes effect on the next request once the registry has reloaded.

## 10. State: Redis, Kafka, Postgres

### 10.1 Redis

Require a password (or ACL users) on Redis. Tokens do not protect it.

| Key | Value | TTL | Written by | Read by |
| --- | --- | --- | --- | --- |
| `idem:{userId}:{key}` | Lifecycle record | 2 min in flight, 24 h after | Gateway | Gateway |
| `deny:sid:{sid}` | Reason | 7 h | auth-service | Gateway, data plane |
| `deny:jti:{jti}` | Marker | Until token expiry | auth-service, data plane | Gateway, data plane |
| `webauthn:chal:{id}` | Challenge | 2 min | auth-service | auth-service |
| `elem:attrs:{elementId}` | Category, area | 60 s, evicted on `element.changed` | Gateway | Gateway |
| `upload:{id}` | Upload session | 24 h | nas-orchestrator | nas-orchestrator, data plane |

### 10.2 Kafka

Use SASL or mTLS between services and per-principal ACLs.

| Topic | Key | Producers | Consumers |
| --- | --- | --- | --- |
| `intent.audit` | `intentId` | Gateway, domain services | Audit store |
| `intent.requested` | `automationId` | Automation engine only (ACL) | Gateway-side executor |
| `session.revoked` | `sid` | auth-service | Data plane, gateway caches |
| `policy.changed` | `domain` | policy-registry | policy-registry replicas |
| `element.changed` | `elementId` | element-registry | Gateway |
| `file.events`, `element.state.changed` | resource ID | Orchestrators | Subscribers |

Audit event shape:

```json
{ "intentId": "018f3a6e-...", "traceId": "...", "name": "nas.file.create",
  "userId": "<userId>", "username": "tamojit",
  "resource": { "type": "WORKSPACE", "id": "tamojit" },
  "stage": "gateway", "effect": "ALLOW", "outcome": "PROCESSED", "status": 201,
  "reasonCode": null, "ts": "2026-11-19T10:00:00Z" }
```

Domain services publish a second event with `stage: service` and the real outcome, under the same `intentId`.

### 10.3 Postgres

| Table | Purpose |
| --- | --- |
| `users` | `id`, `username` (unique, immutable), `role`, `status` |
| `credentials` | Passkey credential ID, public key, signature counter |
| `sessions`, `refresh_tokens` | Section 7.4 |
| `service_clients` | Section 7.7 |
| `policy_rules` | Section 9.1 |
| `resource_grants` | `user_id`, `resource_type`, `resource_id`, `actions`, `granted_by`, `expires_at` |
| `element_assignments` | `user_id`, `element_id` or `area_id` |

## 11. Deployment on fabric .10

### 11.1 Container layout

The addresses below are examples. Substitute your HEARTH host's real address.

```yaml
networks:
  edge: {}
  core:
    internal: true            # no route off the host
  storage: {}                 # egress limited by the host firewall to the NAS address

services:
  api-gateway:
    networks: [edge, core]
    ports: ["10.0.10.5:8443:8443"]       # bind to the HEARTH interface only
    secrets: [gateway_signing_key, tls_cert, tls_key]
  nas-data-plane:
    networks: [edge, core, storage]
    ports: ["10.0.10.5:8444:8444"]
  nas-orchestrator:
    networks: [core, storage]
  auth-service:          { networks: [core] }
  policy-registry:       { networks: [core] }
  element-registry:      { networks: [core] }
  element-orchestrator:  { networks: [core] }
  redis:
    networks: [core]
    command: ["redis-server", "--requirepass", "${REDIS_PASSWORD}"]
  kafka:                 { networks: [core] }
  postgres:              { networks: [core] }
```

- Only the gateway and the data plane publish ports. Everything else is reachable only inside `core`.
- `internal: true` blocks all outbound routes, so the services that must reach the NAS also join `storage`, whose egress the host firewall limits to the NAS address on its API and SMB ports.
- element-orchestrator also needs a path to the IoT fabric for device adapters. Add a dedicated network for it and restrict it the same way. Adapter protocols are outside this document.

### 11.2 Firewall

Between fabrics (OPNsense or equivalent), rules are evaluated top to bottom, first match wins:

| From | To | Port | Action |
| --- | --- | --- | --- |
| Resident fabric | HEARTH host | TCP 8443, 8444 | Allow |
| Guest fabric | HEARTH host | TCP 8443, 8444 | Allow (guest limits are enforced by policy, not the firewall) |
| IoT fabric | HEARTH host | any | Block and log |
| Any client fabric | HEARTH host | everything else | Block and log |
| nas-orchestrator, nas-data-plane host addresses | NAS | TCP 443, 445 | Allow |
| Anything else | NAS | any | Block and log |

On the host, Docker's published ports bypass plain `ufw` and INPUT rules, so put the restriction in the `DOCKER-USER` chain:

```
iptables -I DOCKER-USER -i eth0 -p tcp -m conntrack --ctorigdstport 8443:8444 -j RETURN
iptables -A DOCKER-USER -i eth0 -j DROP
```

Verify the exact rule behaviour on your Docker version. Whatever you use, test it from a client-fabric device (section 14.3).

### 11.3 TLS

The gateway and the data plane present certificates from your local CA, issued for `hearth.local`. Client devices must trust that CA, which WebAuthn also requires. Hops inside `core` use plain HTTP while everything runs on one host. If services ever span hosts, move to mTLS between them. That also proves which service is calling, which the context token does not.

### 11.4 Secrets and clocks

- Signing keys, TLS keys, the Redis password, Kafka credentials and service-client secrets are Docker secrets (mode 0400), never environment variables or images.
- Auth-service and the gateway use separate key pairs.
- All services read the same host clock, with a 5 s skew allowance in every timestamp validator. If services split across hosts, run `chrony` on each.

## 12. Error catalog

| Code | HTTP | Where | Meaning |
| --- | --- | --- | --- |
| `ROUTE_NOT_FOUND` | 404 | Gateway | No route or no `hearth` metadata |
| `AUTH_INVALID` | 401 | Gateway, services | Missing, malformed, expired or wrongly typed credential |
| `SESSION_REVOKED` | 401 | Gateway | `sid` or `jti` on the denylist |
| `AUTH_UNAVAILABLE` | 503 | Gateway | Redis unreachable (fail closed) |
| `VALIDATION_FAILED` | 400, 422 | Gateway | Bad path, params or body |
| `PAYLOAD_TOO_LARGE` | 413 | Gateway | Bounded JSON body over 4 KB |
| `IDEMPOTENCY_KEY_REQUIRED` | 400 | Gateway | Command without `Idempotency-Key` |
| `IDEMPOTENCY_IN_FLIGHT` | 409 | Gateway | Same key still `PROCESSING` |
| `IDEMPOTENCY_KEY_REUSED` | 422 | Gateway | Same key, different request |
| `POLICY_DENIED` | 403 | Gateway | `Decide` returned DENY |
| `POLICY_UNAVAILABLE` | 503 | Gateway | Registry down or timed out (fail closed) |
| `INTENT_BINDING_MISMATCH` | 403 | Services | `bind` does not match the request. Alert |
| `SCOPE_VIOLATION` | 403 | Services | Scope check failed or path escaped the root |
| `CAPABILITY_UNSUPPORTED` | 422 | element-orchestrator | Params not supported by the element |
| `TICKET_INVALID` | 401 | Data plane | Bad, expired or revoked ticket |
| `TICKET_SCOPE_MISMATCH` | 403 | Data plane | Ticket `act` or `res` does not match the request |
| `UPSTREAM_UNAVAILABLE` | 502, 504 | Gateway | Service unreachable or timed out |
| `DEVICE_TIMEOUT` | 202 | element-orchestrator | Command sent, ack pending. Returns `Location` to poll |

## 13. Threat model

| Threat | Attack | Mitigation | Residual risk |
| --- | --- | --- | --- |
| Direct call to a backend port | Client skips the gateway | Firewall allows only 8443 and 8444. Backends on an internal network, no published ports. Token required anyway | Misconfigured firewall. Mitigated by tests in 14.3 |
| Compromised HEARTH service | Calls another service directly | Needs a valid context token, which only the gateway can mint, or a service JWT limited to its scopes | A service can do whatever its own scopes allow |
| Forged identity headers | `X-Hearth-*` or `X-User-Id` from client | Stripped at the gateway. Services read identity only from the signed token | None |
| User access JWT sent to a service | Bypass the gateway with a valid token | Wrong `aud` and no decision. Rejected | None |
| Token replay | Reuse a captured context token | 30 s life, bound to the exact request, optional `jti` store | Same request inside 30 s |
| Checked on X, executed on Y | Alter path or params after the policy check | `bind` over method, path, query, checksum, body | None if encodings match (golden tests) |
| Path traversal | `..`, encoded dots, symlinks | `PathGuard` at the gateway. Normalize, root check and symlink check at the service | None known |
| Stolen ticket | Reuse a ticket URL | Short life, tied to one upload or path prefix, `act` enforced, denylist, URL kept out of logs | Valid until expiry |
| Revoked session still active | Streaming after logout | Gateway checks `deny:sid`. Data plane checks it per request | A few seconds if cached |
| Automation injection | Publish to `intent.requested` | Kafka ACLs. Executor re-runs `Decide` as the creator's current role | Compromised automation engine |
| Gateway compromise | Attacker holds the signing key | Minimal gateway, no business logic, signed images, key in a secret store | Total compromise. Accepted trade-off of a single enforcement point. Future option: policy-registry signs decisions |
| Key compromise | Leaked signing key | Rotation with overlap, short lifetimes, separate keys per issuer | Window until rotation |
| Username reuse or rename | New user inherits an old workspace | Usernames immutable and never reused, restricted charset | None |
| Stale role | Demoted user keeps acting | 15 min access TTL, session revocation on role change | Up to 15 min if revocation is skipped |
| Idempotency abuse | Use another user's key | Key namespaced by `userId`, request hash check | None |
| Denial of service | Flood the gateway or login | Rate limits on public routes, body caps, connection limits | Resource exhaustion on a home-grade host |

## 14. Testing and verification

### 14.1 Unit tests

- `BindCalculator` golden vectors, stored once in `hearth-auth-common` and run by gateway and every service. Include encoded characters, repeated query keys and JSON key ordering.
- `PathGuard`, `Templates.fillPath`, `Paths.resolveUnder`: traversal, double encoding, NUL, backslash.
- `WorkspaceAccess.authorize` for each scope. Include a request for another user's workspace under `OWN`.
- Policy decision algorithm as a table test: specificity ties, DENY-over-ALLOW, no-rule default deny.

### 14.2 Token contract tests

For every service and the data plane, send each of these and assert 401 or 403 with the right code:

| Case | Expected |
| --- | --- |
| Valid token | Accepted |
| Expired | 401 |
| Wrong `aud` (another service's token) | 401 |
| Wrong `typ` (access JWT used as context token, ticket used as context token) | 401 |
| Wrong `iss` | 401 |
| Signed with another key, or `alg=none` | 401 |
| Valid token, path, query, checksum or body altered | 403 `INTENT_BINDING_MISMATCH` |
| Missing `bind` | 403 |

### 14.3 Bypass tests

Run these in CI against the compose stack, and also from a real client-fabric device and a guest device after every firewall change:

1. Direct request to every backend address and port: must time out or be refused.
2. Direct request to `nas-orchestrator` with a stolen valid access JWT: rejected (401).
3. Request through the gateway with a spoofed `X-Hearth-Context` and `X-Hearth-*` headers: stripped, no effect.
4. Request to the data plane control paths: 404, since they do not exist there.
5. Request to `:8444` with an access JWT instead of a ticket: 401.

### 14.4 Integration tests

Use Testcontainers for Redis, Kafka and Postgres. Cover flows A to I from section 5 of the earlier outline and each failure row in section 12. Also cover:

- Ten parallel requests with the same `Idempotency-Key`: exactly one executes, the rest get 409 or a replay.
- policy-registry down: 503, state `DROPPED`, nothing reaches a service.
- Redis down: 503 `AUTH_UNAVAILABLE`.
- Revoke a session mid-stream: the next segment request fails.
- JWKS endpoint unreachable at service start: the service starts from the persisted key set.

### 14.5 Performance and resource checks

Set targets after a first measurement on the real hardware, then keep them as regression gates:

- Added gateway latency for a query with a warm Redis cache and in-memory `Decide`.
- `Decide` call time (should be sub-millisecond inside the registry).
- Data plane cost per HLS segment (signature check plus two Redis reads).
- Gateway heap during a 1 GB upload and download: flat, proving nothing buffers file bodies.

### 14.6 Operational drills

- Rotate the gateway key and the auth key. Confirm overlap works and old tokens fail after it closes.
- Take auth-service down. Existing sessions keep working until expiry, new logins fail cleanly.
- Revoke a session, then confirm both control-plane and ticket requests fail.

## 15. Rollout plan and open decisions

### 15.1 Milestones

| # | Deliverable | Exit test |
| --- | --- | --- |
| M1 | auth-service with passkeys, JWKS, refresh rotation. Gateway authentication filter and sanitizer | Bad and expired tokens dropped at the gateway. Revocation works |
| M2 | Route manifest, intent builder, `Decide` call, one registry with NAS and ELEMENT domains | Allow and deny paths covered, fail closed when the registry is down |
| M3 | Context token, `bind`, `ContextTokenFilter` in nas-orchestrator and element services | Full token contract tests (14.2) pass |
| M4 | Idempotency, lifecycle state, Kafka audit | Concurrency test passes. Every request has an audit trail |
| M5 | Tickets, nas-data-plane, HLS playback and large uploads | Heap-flat transfers. Revocation stops streaming |
| M6 | Network hardening, service JWTs, automation path, key rotation drill | Bypass tests (14.3) pass from a real client device |

### 15.2 Open decisions

| Decision | Options | Current lean |
| --- | --- | --- |
| HLS ticket delivery | Ticket in path or an `HttpOnly` cookie scoped to `/stream` | Path for now. Players cannot set headers. Cookie later if log leakage worries you |
| Signing algorithm | ES256 or EdDSA | ES256: supported by the default Spring decoders |
| Decision integrity | Gateway signs the decision, or policy-registry signs it | Gateway for now. Registry signing removes the gateway's ability to forge ALLOW |
| Internal transport | Plain HTTP on `core` or mTLS | Plain on one host. mTLS once services span hosts |
| Registry split | One registry with two domains, or two registries | One. Splitting is a config change (section 9.4) |
| Username policy | Strictly immutable, or renames with workspace migration | Immutable. A rename needs an atomic migration and revocation of old sessions |
| Replay protection | `jti` store on every command, or only on sensitive routes | Off by default. Turn on per route if needed |

### 15.3 Deferred work

Constraints (quotas, size caps), policy versioning, complex or nested params, ETag and `If-Match` concurrency, decision signing by policy-registry, and mTLS between services.
