package com.antar.hearth.common;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record Intent(
    String intentId,
    String idempotencyKey,
    String name, // AAA.BBB.CCC, e.g. nas.workspace.list
    String action,  // CREATE | READ | LIST | UPDATE | DELETE | STREAM | MANAGE
    Resource resource,
    List<Resource> relatedResources,
    String namespace, // OWNED | SHARED
    Map<String, Object> params,
    Subject subject,
    Instant issuedAt,
    Instant expiredAt,
    Decision decision
) {

    public record Resource(
        String type,
        String id,
        String qualifier,
        Map<String, String> attrs
    ) {
    }

    public record Subject(
        String userId,
        String username,
        String role,
        String sessionId
    ) {
    }

    public record Decision(
        String effect, // effect: ALLOW|DENY
        String scope // scope: OWN|SHARED|ANY
    ) {
    }

    public Intent withDecision(Decision decision) {
        return new Intent(
            intentId,
            idempotencyKey,
            name,
            action,
            resource,
            relatedResources,
            namespace,
            params,
            subject,
            issuedAt,
            expiredAt,
            decision
        );
    }

    public Intent withResource(Resource resource) {
        return new Intent(
            intentId,
            idempotencyKey,
            name,
            action,
            resource,
            relatedResources,
            namespace,
            params,
            subject,
            issuedAt,
            expiredAt,
            decision
        );
    }
}
