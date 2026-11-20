package com.antar.apigateway.gateway;

import com.antar.hearth.common.Intent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class AuditPublisher {
    private static final Logger log = LoggerFactory.getLogger(AuditPublisher.class);

    private final KafkaTemplate<String, Object> kafka;

    public AuditPublisher(KafkaTemplate<String, Object> kafka) {
        this.kafka = kafka;
    }

    public Mono<Void> authRejected(ServerWebExchange ex, String code) {
        return Mono.fromRunnable(() -> {
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("event", "auth.rejected");
            event.put("path", ex.getRequest().getPath().value());
            event.put("method", ex.getRequest().getMethod().name());
            event.put("code", code);
            event.put("timestamp", Instant.now().toString());

            String clientIp = ex.getRequest().getRemoteAddress() != null
                    ? ex.getRequest().getRemoteAddress().getAddress().getHostAddress()
                    : "unknown";
            event.put("clientIp", clientIp);

            log.warn("Authentication rejected: path={}, code={}, clientIp={}",
                    ex.getRequest().getPath().value(), code, clientIp);

            try {
                kafka.send("auth.rejected", clientIp, event);
            } catch (Exception e) {
                log.warn("Failed to publish auth.rejected to Kafka: {}", e.getMessage());
            }
        });
    }

    public Mono<Void> intent(Intent intent, String state, HttpStatusCode status) {
        return Mono.fromRunnable(() -> {
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("intentId", intent.intentId());
            event.put("name", intent.name());
            event.put("userId", intent.subject() != null ? intent.subject().userId() : null);
            event.put("username", intent.subject() != null ? intent.subject().username() : null);
            event.put("resource", intent.resource());
            event.put("stage", "gateway");
            event.put("effect", intent.decision() != null ? intent.decision().effect() : null);
            event.put("outcome", state);
            event.put("status", status != null ? status.value() : null);
            event.put("ts", Instant.now().toString());

            log.info("Intent audit: intentId={}, name={}, outcome={}, status={}",
                    intent.intentId(), intent.name(), state, status);

            try {
                kafka.send("intent.audit", intent.intentId(), event);
            } catch (Exception e) {
                log.warn("Failed to publish intent.audit to Kafka: {}", e.getMessage());
            }
        });
    }
}
