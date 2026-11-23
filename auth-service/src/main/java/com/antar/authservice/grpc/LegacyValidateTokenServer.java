package com.antar.authservice.grpc;

import com.antar.authservice.config.AuthKeys;
import com.antar.grpc.auth.AuthGrpcServiceGrpc;
import com.antar.grpc.auth.ValidateTokenRequest;
import com.antar.grpc.auth.ValidateTokenResponse;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.grpc.server.service.GrpcService;

import java.util.Date;
import java.util.List;

@GrpcService
public class LegacyValidateTokenServer extends AuthGrpcServiceGrpc.AuthGrpcServiceImplBase {
    private static final Logger log = LoggerFactory.getLogger(LegacyValidateTokenServer.class);
    private final AuthKeys keys;

    public LegacyValidateTokenServer(AuthKeys keys) {
        this.keys = keys;
    }

    @Override
    public void validateToken(ValidateTokenRequest request,
                              StreamObserver<ValidateTokenResponse> resp) {
        // DO NOT log request token directly
        try {
            SignedJWT jwt = SignedJWT.parse(request.getToken());
            String kid = jwt.getHeader().getKeyID();
            ECKey key = keys.getKey(kid);
            if (key == null) {
                log.warn("ValidateToken: Key ID not found: {}", kid);
                resp.onNext(ValidateTokenResponse.newBuilder().setValid(false).build());
                resp.onCompleted();
                return;
            }

            if (!jwt.verify(new ECDSAVerifier(key.toECPublicKey()))) {
                log.warn("ValidateToken: Signature verification failed");
                resp.onNext(ValidateTokenResponse.newBuilder().setValid(false).build());
                resp.onCompleted();
                return;
            }

            JWTClaimsSet c = jwt.getJWTClaimsSet();
            Date exp = c.getExpirationTime();
            if (exp != null && exp.before(new Date())) {
                log.warn("ValidateToken: Token expired at {}", exp);
                resp.onNext(ValidateTokenResponse.newBuilder().setValid(false).build());
                resp.onCompleted();
                return;
            }

            if (!"hearth-auth".equals(c.getIssuer())) {
                log.warn("ValidateToken: Invalid issuer: {}", c.getIssuer());
                resp.onNext(ValidateTokenResponse.newBuilder().setValid(false).build());
                resp.onCompleted();
                return;
            }

            List<String> aud = c.getAudience();
            if (aud == null || aud.isEmpty()) {
                log.warn("ValidateToken: Missing audience");
                resp.onNext(ValidateTokenResponse.newBuilder().setValid(false).build());
                resp.onCompleted();
                return;
            }

            String userId = c.getSubject() != null ? c.getSubject() : "";
            String username = c.getStringClaim("username");
            if (username == null) {
                username = userId;
            }
            String role = c.getStringClaim("role");
            if (role == null) {
                role = "SERVICE";
            }

            resp.onNext(ValidateTokenResponse.newBuilder()
                .setValid(true)
                .setUserId(userId)
                .setUsername(username)
                .setRole(role)
                .build());
        } catch (Exception e) {
            log.warn("LegacyValidateTokenServer exception: {}", e.getMessage());
            resp.onNext(ValidateTokenResponse.newBuilder().setValid(false).build());
        }

        resp.onCompleted();
    }
}
