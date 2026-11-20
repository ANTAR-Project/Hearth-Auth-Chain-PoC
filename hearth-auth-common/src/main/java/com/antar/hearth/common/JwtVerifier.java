package com.antar.hearth.common;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

public final class JwtVerifier {

    public record Spec(
        String typ,
        String issuer,
        String audience,
        Duration skew
    ) {
    }

    public static class Rejected extends RuntimeException {
        public Rejected(String reason) {
            super(reason);
        }
    }

    public static class Unavailable extends RuntimeException {
        public Unavailable(Throwable cause) {
            super(cause);
        }
    }

    private final JWKSource<SecurityContext> jwks;
    private final Spec spec;

    public JwtVerifier(JWKSource<SecurityContext> jwks, Spec spec) {
        this.jwks = jwks;
        this.spec = spec;
    }

    public JWTClaimsSet verify(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWSHeader header = jwt.getHeader();

            if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
                throw new Rejected("alg");
            }

            if (header.getType() == null || !spec.typ().equals(header.getType().getType())) {
                throw new Rejected("typ");
            }

            List<JWK> keys = jwks.get(
                new JWKSelector(new JWKMatcher.Builder()
                    .keyType(KeyType.EC)
                    .keyID(header.getKeyID())
                    .build()), null
            );
            if (keys.isEmpty()) {
                throw new Rejected("kid");
            }

            ECPublicKey pubKey = ((ECKey) keys.get(0)).toECPublicKey();
            if (!jwt.verify(new ECDSAVerifier(pubKey))) {
                throw new Rejected("sig");
            }

            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            if (!spec.issuer().equals(claimsSet.getIssuer())) {
                throw new Rejected("iss");
            }

            List<String> aud = claimsSet.getAudience();
            if (aud == null || !aud.contains(spec.audience())) {
                throw new Rejected("aud");
            }

            Date exp = claimsSet.getExpirationTime();
            if (exp == null || Instant.now().isAfter(exp.toInstant().plus(spec.skew()))) {
                throw new Rejected("exp");
            }

            return claimsSet;
        } catch (KeySourceException e) {
            throw new Unavailable(e);
        } catch (ParseException | JOSEException e) {
            throw new Rejected("malformed: " + e.getMessage());
        }
    }
}
