package com.antar.apigateway.gateway;

import com.antar.apigateway.config.GatewayKeys;
import com.antar.hearth.common.Hearth;
import com.antar.hearth.common.Intent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class ContextTokenMinter {
    private final GatewayKeys keys;

    public ContextTokenMinter(GatewayKeys keys) {
        this.keys = keys;
    }

    public String mint(Intent intent, String audience, String bind) {
        Instant now = Instant.now();

        Map<String, Object> res = new LinkedHashMap<>();
        if (intent.resource() != null) {
            res.put("type", intent.resource().type());
            res.put("id", intent.resource().id());
            if (intent.resource().qualifier() != null) {
                res.put("qualifier", intent.resource().qualifier());
            }
        }

        Map<String, Object> decision = new LinkedHashMap<>();
        if (intent.decision() != null) {
            decision.put("effect", intent.decision().effect());
            decision.put("scope", intent.decision().scope());
        } else {
            decision.put("effect", "ALLOW");
            decision.put("scope", "ANY");
        }

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer(Hearth.ISS_GATEWAY)
            .audience(audience)
            .subject(intent.subject().userId())
            .claim("username", intent.subject().username())
            .claim("role", intent.subject().role())
            .claim("sid", intent.subject().sessionId())
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(30)))
            .jwtID(UUID.randomUUID().toString())
            .claim("intentId", intent.intentId())
            .claim("name", intent.name())
            .claim("action", intent.action())
            .claim("res", res)
            .claim("ns", intent.namespace() != null ? intent.namespace() : "OWN")
            .claim("decision", decision)
            .claim("bind", bind)
            .build();

        try {
            ECKey key = keys.current();
            SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(key.getKeyID())
                    .type(new JOSEObjectType(Hearth.TYP_CTX))
                    .build(),
                claims
            );
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Context token signing failed", e);
        }
    }
}
