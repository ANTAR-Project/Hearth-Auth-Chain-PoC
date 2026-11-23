package com.antar.policyregistry.engine;

import com.antar.grpc.policy.DecideRequest;
import com.antar.grpc.policy.DecideResponse;
import com.antar.policyregistry.model.PolicyEffect;
import com.antar.policyregistry.model.PolicyRule;
import com.antar.policyregistry.model.PolicyScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class DecisionEngine {
    private static final Logger log = LoggerFactory.getLogger(DecisionEngine.class);
    private final AtomicReference<RuleSnapshot> snapshot = new AtomicReference<>(RuleSnapshot.EMPTY);

    public void setSnapshot(RuleSnapshot s) {
        snapshot.set(s);
    }

    public RuleSnapshot getSnapshot() {
        return snapshot.get();
    }

    public DecideResponse decide(DecideRequest decideRequest) {
        String domain = decideRequest.getDomain();
        String role = decideRequest.getSubject().getRole();
        String action = decideRequest.getAction();
        String resType = decideRequest.getResource().getType();
        String qualifier = decideRequest.getResource().getQualifier();

        List<PolicyRule> matching = snapshot.get()
            .rulesForDomain(domain)
            .stream()
            .filter(r -> r.getRole().equalsIgnoreCase(role))
            .filter(r -> r.getAction().equalsIgnoreCase(action))
            .filter(r -> r.getResourceType().equalsIgnoreCase(resType))
            .filter(r -> r.getResourceQualifier() == null
                || r.getResourceQualifier().equalsIgnoreCase(qualifier))
            .toList();

        DecideResponse response;
        if (matching.isEmpty()) {
            response = DecideResponse.newBuilder()
                .setEffect("DENY")
                .setReasonCode("NO_MATCHING_RULE")
                .build();
        } else if (matching.stream().anyMatch(r -> r.getEffect() == PolicyEffect.DENY)) {
            response = DecideResponse.newBuilder()
                .setEffect("DENY")
                .setReasonCode("EXPLICIT_DENY")
                .build();
        } else {
            PolicyRule best = matching.stream()
                .filter(r -> r.getEffect() == PolicyEffect.ALLOW)
                .max(Comparator.comparingInt(PolicyRule::getPriority)
                    .thenComparing(r -> r.getResourceQualifier() != null)
                    .thenComparing(r -> scopeBreadth(r.getScope())))
                .orElse(null);

            if (best == null) {
                response = DecideResponse.newBuilder()
                    .setEffect("DENY")
                    .setReasonCode("NO_ALLOW_RULE")
                    .build();
            } else if (!"OWNER".equalsIgnoreCase(role) && "DELETE".equalsIgnoreCase(action)
                    && ("WORKSPACE".equalsIgnoreCase(resType) || decideRequest.getRuleName().contains("workspace.delete"))) {
                // Workspace permanent deletion is OWNER only
                response = DecideResponse.newBuilder()
                    .setEffect("DENY")
                    .setReasonCode("WORKSPACE_DELETE_OWNER_ONLY")
                    .build();
            } else if (!"OWNER".equalsIgnoreCase(role) && best.getScope() == PolicyScope.OWN
                    && ("OTHER".equalsIgnoreCase(decideRequest.getNamespace())
                        || (decideRequest.getResource().getId() != null && !decideRequest.getResource().getId().isEmpty()
                            && !decideRequest.getResource().getId().equalsIgnoreCase(decideRequest.getSubject().getUsername())))) {
                // Cross-user access check: OWN scope cannot access another user's resources
                response = DecideResponse.newBuilder()
                    .setEffect("DENY")
                    .setReasonCode("CROSS_USER_ACCESS_DENIED")
                    .build();
            } else {
                response = DecideResponse.newBuilder()
                    .setEffect("ALLOW")
                    .setScope(best.getScope().name())
                    .setReasonCode("RULE:" + best.getRuleName())
                    .build();
            }
        }

        log.info("================================================================================");
        log.info("[POLICY_REGISTRY_INTENT_DECISION] Evaluated Intent Decision");
        log.info("  Intent / Rule : {}", decideRequest.getRuleName().isEmpty() ? "N/A" : decideRequest.getRuleName());
        log.info("  Domain        : {}", domain);
        log.info("  Subject       : {} (Role: {}, UserId: {})", decideRequest.getSubject().getUsername(), role, decideRequest.getSubject().getUserId());
        log.info("  Action        : {}", action);
        log.info("  Resource      : Type={}, Id={}, Qualifier={}", resType, decideRequest.getResource().getId(), qualifier);
        log.info("  Namespace     : {}", decideRequest.getNamespace());
        log.info("  Decision      : Effect={}, Scope={}, ReasonCode={}", response.getEffect(), response.getScope(), response.getReasonCode());
        log.info("================================================================================");

        return response;
    }

    private int scopeBreadth(PolicyScope scope) {
        return switch (scope) {
            case OWN -> 0;
            case SHARED -> 1;
            case ANY -> 2;
        };
    }
}
