package com.antar.elementregistry.hearth;

import com.nimbusds.jwt.JWTClaimsSet;

import java.util.Map;

public record HearthPrincipal(
    String type,
    String userId,
    String username,
    String role,
    String sessionId,
    String intentId,
    String intentName,
    String action,
    String resourceType,
    String resourceId,
    String qualifier,
    String namespace,
    String scope
) {
    public static final String ATTR = "hearth.principal";

    @SuppressWarnings("unchecked")
    public static HearthPrincipal fromContextToken(JWTClaimsSet c) throws Exception {
        Map<String, Object> res = (Map<String, Object>) c.getClaim("res");
        Map<String, Object> dec = (Map<String, Object>) c.getClaim("decision");

        return new HearthPrincipal(
            "USER",
            c.getSubject(),
            c.getStringClaim("username"),
            c.getStringClaim("role"),
            c.getStringClaim("sid"),
            c.getStringClaim("intentId"),
            c.getStringClaim("name"),
            c.getStringClaim("action"),
            (String) res.get("type"),
            (String) res.get("id"),
            (String) res.get("qualifier"),
            c.getStringClaim("ns"),
            (String) dec.get("scope")
        );
    }
}
