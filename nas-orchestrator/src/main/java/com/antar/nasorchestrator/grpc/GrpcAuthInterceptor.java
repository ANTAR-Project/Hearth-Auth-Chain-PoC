package com.antar.nasorchestrator.grpc;

import com.antar.hearth.common.JwtVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import io.grpc.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.stereotype.Component;

@Component
@GlobalServerInterceptor
public class GrpcAuthInterceptor implements ServerInterceptor {
    private static final Logger log = LoggerFactory.getLogger(GrpcAuthInterceptor.class);
    public static final Context.Key<String> USERNAME_CONTEXT_KEY = Context.key("authUsername");
    private static final Metadata.Key<String> AUTH_TOKEN_METADATA_KEY =
        Metadata.Key.of("x-auth-token", Metadata.ASCII_STRING_MARSHALLER);

    private final JwtVerifier serviceTokenVerifier;

    public GrpcAuthInterceptor(JwtVerifier serviceTokenVerifier) {
        this.serviceTokenVerifier = serviceTokenVerifier;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
        ServerCall<ReqT, RespT> call,
        Metadata headers,
        ServerCallHandler<ReqT, RespT> next
    ) {
        String token = headers.get(AUTH_TOKEN_METADATA_KEY);

        if (token == null || token.isBlank()) {
            call.close(Status.UNAUTHENTICATED.withDescription("Missing x-auth-token metadata"), new Metadata());
            return new ServerCall.Listener<>() {};
        }

        try {
            JWTClaimsSet claims = serviceTokenVerifier.verify(token);
            String subject = claims.getSubject(); // "svc:<clientId>"
            log.info("[GRPC_AUTH_ACCEPTED] Service token verified: subject={}", subject);
            Context context = Context.current().withValue(USERNAME_CONTEXT_KEY, subject);
            return Contexts.interceptCall(context, call, headers, next);
        } catch (JwtVerifier.Rejected e) {
            log.warn("[GRPC_AUTH_REJECTED] Service token rejected: {}", e.getMessage());
            call.close(Status.UNAUTHENTICATED.withDescription("Token is invalid, expired, or was revoked"), new Metadata());
            return new ServerCall.Listener<>() {};
        } catch (JwtVerifier.Unavailable e) {
            log.error("[GRPC_AUTH_UNAVAILABLE] Auth key material unavailable: {}", e.getMessage());
            call.close(Status.UNAVAILABLE.withDescription("Auth key material temporarily unavailable"), new Metadata());
            return new ServerCall.Listener<>() {};
        }
    }
}
