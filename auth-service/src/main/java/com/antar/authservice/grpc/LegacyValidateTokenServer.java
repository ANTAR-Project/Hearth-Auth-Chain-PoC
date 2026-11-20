package com.antar.authservice.grpc;

import com.antar.authservice.config.AuthKeys;
import com.antar.grpc.auth.AuthGrpcServiceGrpc;
import com.antar.grpc.auth.ValidateTokenRequest;
import com.antar.grpc.auth.ValidateTokenResponse;
import com.antar.hearth.common.JwtVerifier;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import io.grpc.stub.StreamObserver;
import org.springframework.grpc.server.service.GrpcService;

import java.time.Duration;

@GrpcService
public class LegacyValidateTokenServer extends AuthGrpcServiceGrpc.AuthGrpcServiceImplBase {
    private final AuthKeys keys;

    public LegacyValidateTokenServer(AuthKeys keys) {
        this.keys = keys;
    }

    @Override
    public void validateToken(ValidateTokenRequest request,
                              StreamObserver<ValidateTokenResponse> resp) {
        // DO NOT log request — it contains the token
        try {
            JwtVerifier verifier = new JwtVerifier(
                new ImmutableJWKSet<>(keys.publicJwkSet()),
                new JwtVerifier.Spec("at+jwt", "hearth-auth", "hearth-gateway",
                    Duration.ofSeconds(5)));

            JWTClaimsSet c = verifier.verify(request.getToken());

            resp.onNext(ValidateTokenResponse.newBuilder()
                .setValid(true).setUserId(c.getSubject())
                .setUsername(c.getStringClaim("username"))
                .setRole(c.getStringClaim("role")).build());
        } catch (Exception e) {
            resp.onNext(ValidateTokenResponse.newBuilder().setValid(false).build());
        }

        resp.onCompleted();
    }
}