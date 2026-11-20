package com.antar.apigateway.filter;

import com.antar.apigateway.gateway.AuditPublisher;
import com.antar.apigateway.gateway.Problems;
import com.antar.apigateway.gateway.RouteMeta;
import com.antar.hearth.common.Intent;
import com.antar.hearth.common.JwtVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {
    public static final String SUBJECT_ATTR = "hearth.subject";

    private final JwtVerifier accessVerifier;
    private final ReactiveStringRedisTemplate redis;
    private final AuditPublisher audit;

    public AuthenticationFilter(
        JwtVerifier accessVerifier,
        ReactiveStringRedisTemplate redis,
        AuditPublisher audit
    ) {
        this.accessVerifier = accessVerifier;
        this.redis = redis;
        this.audit = audit;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange ex,
                             GatewayFilterChain chain) {
        RouteMeta meta = RouteMeta.of(ex);
        if (meta == null) return Problems.write(ex, 404, "ROUTE_NOT_FOUND");
        if (meta.publicRoute()) return chain.filter(ex);

        String auth = ex.getRequest()
            .getHeaders()
            .getFirst(HttpHeaders.AUTHORIZATION);

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

    private Mono<Void> checkRevoked(ServerWebExchange ex, GatewayFilterChain chain, JWTClaimsSet c) {
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

    static class RejectRequest extends RuntimeException {
        private final int status;
        private final String code;

        public RejectRequest(int status, String code) {
            super(code);
            this.status = status;
            this.code = code;
        }

        public int status() {
            return status;
        }

        public String code() {
            return code;
        }
    }

    @Override
    public int getOrder() {
        return -250;
    }
}