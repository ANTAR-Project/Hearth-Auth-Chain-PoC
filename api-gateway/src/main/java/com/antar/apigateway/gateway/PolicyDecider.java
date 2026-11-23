package com.antar.apigateway.gateway;

import com.antar.grpc.policy.DecideRequest;
import com.antar.grpc.policy.DecideResponse;
import com.antar.grpc.policy.PolicyGrpc;
import com.antar.grpc.policy.Resource;
import com.antar.grpc.policy.Subject;
import com.antar.hearth.common.Intent;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Component
public class PolicyDecider {
    private static final Logger log = LoggerFactory.getLogger(PolicyDecider.class);

    private final String nasEndpoint;
    private final String elementEndpoint;
    private final Map<String, ManagedChannel> channels = new ConcurrentHashMap<>();
    private final Map<String, PolicyGrpc.PolicyBlockingStub> stubs = new ConcurrentHashMap<>();

    public PolicyDecider(
        @Value("${hearth.policy.endpoints.NAS:policy-registry:9001}") String nasEndpoint,
        @Value("${hearth.policy.endpoints.ELEMENT:policy-registry:9001}") String elementEndpoint
    ) {
        this.nasEndpoint = nasEndpoint;
        this.elementEndpoint = elementEndpoint;
    }

    private PolicyGrpc.PolicyBlockingStub getStub(String domain) {
        String endpoint = "ELEMENT".equalsIgnoreCase(domain) ? elementEndpoint : nasEndpoint;
        return stubs.computeIfAbsent(endpoint, ep -> {
            String[] parts = ep.split(":");
            String host = parts[0];
            int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 9001;
            log.info("[POLICY_GRPC_CHANNEL] Initializing ManagedChannel to policy-registry at {}:{}", host, port);
            ManagedChannel ch = ManagedChannelBuilder.forAddress(host, port)
                .usePlaintext()
                .build();
            channels.put(endpoint, ch);
            return PolicyGrpc.newBlockingStub(ch);
        });
    }

    public Intent.Decision decide(RouteMeta meta, Intent.Subject subject, ServerHttpRequest req) {
        return decide(meta, subject, null, req);
    }

    public Intent.Decision decide(RouteMeta meta, Intent.Subject subject, String resId, ServerHttpRequest req) {
        String role = subject.role() != null ? subject.role().toUpperCase() : "GUEST";
        String action = meta.action() != null ? meta.action().toUpperCase() : req.getMethod().name();
        String domain = meta.domain() != null ? meta.domain().toUpperCase() : "NAS";
        String resType = meta.resourceType() != null ? meta.resourceType().toUpperCase() : "WORKSPACE";
        String qualifier = meta.qualifier() != null ? meta.qualifier() : "";
        String namespace = meta.namespace() != null ? meta.namespace().toUpperCase() : "OWN";
        String ruleName = meta.intent() != null ? meta.intent() : "";

        // Check for cross-user workspace access attempt
        String requestedUser = req.getQueryParams().getFirst("user");
        if (requestedUser == null) {
            requestedUser = req.getQueryParams().getFirst("username");
        }
        if (requestedUser == null) {
            requestedUser = req.getQueryParams().getFirst("workspace");
        }
        if (requestedUser != null && !requestedUser.equalsIgnoreCase(subject.username())) {
            namespace = "OTHER";
        }

        Subject protoSubject = Subject.newBuilder()
            .setUserId(subject.userId() != null ? subject.userId() : "")
            .setUsername(subject.username() != null ? subject.username() : "")
            .setRole(role)
            .build();

        String finalResId = resId != null ? resId : (requestedUser != null ? requestedUser : subject.username());
        Resource protoResource = Resource.newBuilder()
            .setType(resType)
            .setId(finalResId != null ? finalResId : "")
            .setQualifier(qualifier)
            .build();

        DecideRequest request = DecideRequest.newBuilder()
            .setDomain(domain)
            .setSubject(protoSubject)
            .setAction(action)
            .setResource(protoResource)
            .setNamespace(namespace)
            .setRuleName(ruleName)
            .build();

        log.info("[POLICY_GRPC_CALL] Forwarding intent to policy-registry via gRPC: domain='{}', action='{}', user='{}', role='{}', intent='{}'",
            domain, action, subject.username(), role, ruleName);

        try {
            DecideResponse response = getStub(domain)
                .withDeadlineAfter(5, TimeUnit.SECONDS)
                .decide(request);

            log.info("[POLICY_GRPC_DECISION] Decision received from policy-registry: effect='{}', scope='{}', reason='{}'",
                response.getEffect(), response.getScope(), response.getReasonCode());

            return new Intent.Decision(response.getEffect(), response.getScope());
        } catch (Exception e) {
            log.error("[POLICY_GRPC_ERROR] gRPC call to policy-registry failed: {}", e.getMessage(), e);
            return new Intent.Decision("DENY", null);
        }
    }

    @PreDestroy
    public void cleanup() {
        for (ManagedChannel ch : channels.values()) {
            try {
                ch.shutdown().awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
            }
        }
    }
}
