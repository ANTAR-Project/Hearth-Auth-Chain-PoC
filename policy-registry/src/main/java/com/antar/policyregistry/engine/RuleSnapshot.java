package com.antar.policyregistry.engine;

import com.antar.policyregistry.model.PolicyRule;

import java.util.*;

public record RuleSnapshot(
    Map<String, List<PolicyRule>> byDomain
) {
    public static final RuleSnapshot EMPTY = new RuleSnapshot(Map.of());

    public List<PolicyRule> rulesForDomain(String domain) {
        return byDomain.getOrDefault(domain.toUpperCase(), List.of());
    }

    public static RuleSnapshot from(List<PolicyRule> all) {
        Map<String, List<PolicyRule>> map = new HashMap<>();

        for (PolicyRule policyRule : all) {
            if (policyRule.isEnabled()) {
                map.computeIfAbsent(policyRule.getDomain().toUpperCase(),
                    k -> new ArrayList<>()).add(policyRule);
            }
        }

        return new RuleSnapshot(Collections.unmodifiableMap(map));
    }
}
