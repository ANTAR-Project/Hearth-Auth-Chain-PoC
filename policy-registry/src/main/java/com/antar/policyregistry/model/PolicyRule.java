package com.antar.policyregistry.model;

import jakarta.persistence.*;

import java.util.UUID;

@Entity
@Table(name = "policy_rules")
public class PolicyRule {

    @Id
    private UUID id;

    @Column(name = "rule_name", nullable = false)
    private String ruleName;

    @Column(nullable = false)
    private String domain;

    @Column(nullable = false)
    private String role;

    @Column(nullable = false)
    private String action;

    @Column(name = "resource_type", nullable = false)
    private String resourceType;

    @Column(name = "resource_qualifier")
    private String resourceQualifier;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PolicyScope scope;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PolicyEffect effect;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false)
    private int priority = 0;

    public UUID getId() {
        return id;
    }

    public String getRuleName() {
        return ruleName;
    }

    public String getDomain() {
        return domain;
    }

    public String getRole() {
        return role;
    }

    public String getAction() {
        return action;
    }

    public String getResourceType() {
        return resourceType;
    }

    public String getResourceQualifier() {
        return resourceQualifier;
    }

    public PolicyScope getScope() {
        return scope;
    }

    public PolicyEffect getEffect() {
        return effect;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getPriority() {
        return priority;
    }
}
