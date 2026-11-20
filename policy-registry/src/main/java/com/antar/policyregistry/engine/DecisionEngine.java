package com.antar.policyregistry.engine;

import com.antar.grpc.policy.DecideRequest;
import com.antar.grpc.policy.DecideResponse;
import com.antar.policyregistry.model.PolicyEffect;
import com.antar.policyregistry.model.PolicyRule;
import com.antar.policyregistry.model.PolicyScope;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class DecisionEngine {
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

        if (matching.isEmpty()) {
            return DecideResponse.newBuilder()
                .setEffect("DENY")
                .setReasonCode("NO_MATCHING_RULE")
                .build();
        }

        boolean denied = matching.stream()
            .anyMatch(r -> r.getEffect() == PolicyEffect.DENY);
        if (denied) {
            return DecideResponse.newBuilder()
                .setEffect("DENY")
                .setReasonCode("EXPLICIT_DENY")
                .build();
        }

        PolicyRule best = matching.stream()
            .filter(r -> r.getEffect() == PolicyEffect.ALLOW)
            .max(Comparator.comparingInt(PolicyRule::getPriority)
                .thenComparing(r -> r.getResourceQualifier() != null)
                .thenComparing(r -> scopeBreadth(r.getScope())))
            .orElse(null);
        if (best == null) {
            return DecideResponse.newBuilder()
                .setEffect("DENY")
                .setReasonCode("NO_ALLOW_RULE")
                .build();
        }

        return DecideResponse.newBuilder()
            .setEffect("ALLOW")
            .setScope(best.getScope().name())
            .setReasonCode("RULE:" + best.getRuleName())
            .build();
    }

    private int scopeBreadth(PolicyScope scope) {
        return switch (scope) {
            case OWN -> 0;
            case SHARED -> 1;
            case ANY -> 2;
        };
    }
}
