package com.antar.apigateway.filter;

import com.antar.apigateway.gateway.AuditPublisher;
import com.antar.apigateway.gateway.ContextTokenMinter;
import com.antar.apigateway.gateway.PolicyDecider;
import com.antar.apigateway.gateway.Problems;
import com.antar.apigateway.gateway.RouteMeta;
import com.antar.hearth.common.BindCalculator;
import com.antar.hearth.common.Hearth;
import com.antar.hearth.common.Intent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Mint and forward a short-lived Context Token (X-Hearth-Context) to downstream services (PEP #2).
 * Runs at order 100 — after AuthenticationFilter (-250) and path rewriting (1..5), but before routing (10000).
 */
@Component
public class ForwardFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(ForwardFilter.class);

    private final ContextTokenMinter minter;
    private final PolicyDecider policyDecider;
    private final AuditPublisher audit;

    public ForwardFilter(
        ContextTokenMinter minter,
        PolicyDecider policyDecider,
        AuditPublisher audit
    ) {
        this.minter = minter;
        this.policyDecider = policyDecider;
        this.audit = audit;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange ex, GatewayFilterChain chain) {
        RouteMeta meta = RouteMeta.of(ex);
        if (meta == null || meta.publicRoute() || meta.audience() == null) {
            return chain.filter(ex);
        }

        Intent.Subject subject = ex.getAttribute(AuthenticationFilter.SUBJECT_ATTR);
        if (subject == null) {
            return chain.filter(ex);
        }

        // Resolve resource ID placeholders
        String resId = meta.resourceId();
        if (resId == null) {
            resId = subject.username();
        } else {
            resId = resId.replace("{username}", subject.username())
                         .replace("{userId}", subject.userId());
            Map<String, String> vars = ServerWebExchangeUtils.getUriTemplateVariables(ex);
            if (vars != null) {
                for (Map.Entry<String, String> entry : vars.entrySet()) {
                    resId = resId.replace("{" + entry.getKey() + "}", entry.getValue());
                }
            }
        }

        // Policy check
        Intent.Decision decision;
        if (meta.skipPolicy()) {
            decision = new Intent.Decision("ALLOW", "ANY");
        } else {
            decision = policyDecider.decide(meta, subject, resId, ex.getRequest());
        }

        String intentId = UUID.randomUUID().toString();
        Intent intent = new Intent(
            intentId,
            ex.getRequest().getHeaders().getFirst("Idempotency-Key"),
            meta.intent() != null ? meta.intent() : "intent.default",
            meta.action() != null ? meta.action() : ex.getRequest().getMethod().name(),
            new Intent.Resource(
                meta.resourceType() != null ? meta.resourceType() : "RESOURCE",
                resId,
                meta.qualifier(),
                Map.of()
            ),
            List.of(),
            meta.namespace() != null ? meta.namespace() : "OWN",
            Map.of(),
            subject,
            Instant.now(),
            Instant.now().plusSeconds(30),
            decision
        );

        if (!"ALLOW".equalsIgnoreCase(decision.effect())) {
            return audit.intent(intent, "DENIED", HttpStatus.FORBIDDEN)
                .then(Problems.write(ex, 403, "POLICY_DENIED"));
        }

        // Compute bind hash using the path that upstream service will receive
        String upstreamPath = ex.getRequest().getPath().value();
        String rawQuery = ex.getRequest().getURI().getRawQuery();
        String checksum = ex.getRequest().getHeaders().getFirst("X-Checksum-SHA256");

        String bind = BindCalculator.bind(
            ex.getRequest().getMethod().name(),
            upstreamPath,
            rawQuery,
            checksum,
            null
        );

        // Mint Context Token
        String contextToken = minter.mint(intent, meta.audience(), bind);

        log.info("================================================================================");
        log.info("[CONTEXT_TOKEN_GENERATED] Target Service: [{}]", meta.audience());
        log.info("  Request : {} {}", ex.getRequest().getMethod().name(), ex.getRequest().getPath().value());
        log.info("  Subject : {} (Role: {}, SID: {})", subject.username(), subject.role(), subject.sessionId());
        log.info("  Intent  : {} (Action: {})", intent.name(), intent.action());
        log.info("  Token   : {}", contextToken);
        log.info("================================================================================");

        // Attach context token and target service to response headers for testing / debugging
        ex.getResponse().beforeCommit(() -> {
            ex.getResponse().getHeaders().set("X-Hearth-Context", contextToken);
            ex.getResponse().getHeaders().set("X-Hearth-Target-Service", meta.audience());
            return Mono.empty();
        });

        // Mutate outgoing request: strip client Bearer token, attach context token and intent ID
        ServerHttpRequest out = ex.getRequest().mutate()
            .headers(h -> {
                h.remove(HttpHeaders.AUTHORIZATION);
                h.set(Hearth.CTX_HEADER, contextToken);
                h.set(Hearth.INTENT_HEADER, intentId);
            })
            .build();

        return audit.intent(intent, "ALLOWED", HttpStatus.OK)
            .then(chain.filter(ex.mutate().request(out).build()));
    }

    @Override
    public int getOrder() {
        return 100;
    }
}
