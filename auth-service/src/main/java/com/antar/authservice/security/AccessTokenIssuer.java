package com.antar.authservice.security;

import com.nimbusds.jwt.JWTClaimsSet;
import com.antar.authservice.config.AuthKeys;
import com.antar.authservice.model.User;
import com.antar.hearth.common.Hearth;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
public class AccessTokenIssuer {
    private final AuthKeys keys;
    public AccessTokenIssuer(AuthKeys keys) { this.keys = keys; }
    public String issue(User u, UUID sessionId, List<String> amr) {
        try {
            Instant now = Instant.now();

            JWTClaimsSet.Builder c = new JWTClaimsSet.Builder()
                .issuer(Hearth.ISS_AUTH).audience("hearth-gateway")
                .subject(u.getId().toString())
                .claim("username", u.getUsername()).claim("role", u.getRole().name())
                .claim("sid", sessionId.toString()).claim("amr", amr)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(900)))
                .jwtID(UUID.randomUUID().toString());

            if (u.isMustChangePassword()) c.claim("scope", "pwd-change");
            return keys.sign(c.build(), "at+jwt");
        } catch (Exception e) {
            throw new IllegalStateException("Access token signing failed", e);
        }
    }
    public String issueService(String clientId, String audience, String scope) {
        try {
            Instant now = Instant.now();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(Hearth.ISS_AUTH).audience(audience)
                .subject("svc:" + clientId).claim("scope", scope)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(600)))
                .jwtID(UUID.randomUUID().toString()).build();
            
            return keys.sign(claims, "at+jwt");
        } catch (Exception e) {
            throw new IllegalStateException("Service token signing failed", e);
        }
    }
}
