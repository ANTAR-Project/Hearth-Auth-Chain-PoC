package com.antar.notificationservice.websocket;

import com.antar.hearth.common.JwtVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Validates the caller's access JWT BEFORE upgrading the connection to a WebSocket.
 * Browsers cannot attach custom headers to a WebSocket handshake request,
 * so the access token travels as ?token= query parameter instead.
 * We verify it directly with JwtVerifier (no gRPC round-trip needed).
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TokenHandshakeInterceptor implements HandshakeInterceptor {
    private final JwtVerifier accessTokenVerifier;

    @Override
    public boolean beforeHandshake(
        ServerHttpRequest request,
        ServerHttpResponse response,
        WebSocketHandler wsHandler,
        Map<String, Object> attributes
    ) {
        String token = extractToken(request);

        if (token == null) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return false;
        }

        try {
            JWTClaimsSet claims = accessTokenVerifier.verify(token);
            String username = claims.getStringClaim("username");
            if (username == null || username.isBlank()) {
                log.warn("Access token has no username claim during WebSocket handshake");
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return false;
            }
            attributes.put("username", username);
            return true;
        } catch (JwtVerifier.Rejected e) {
            log.warn("WebSocket handshake rejected — invalid access token");
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return false;
        } catch (JwtVerifier.Unavailable e) {
            log.warn("JWKS unavailable during WebSocket handshake");
            response.setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
            return false;
        } catch (Exception e) {
            log.error("Unexpected error during WebSocket handshake token verification", e);
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return false;
        }
    }

    @Override
    public void afterHandshake(
        ServerHttpRequest request,
        ServerHttpResponse response,
        WebSocketHandler wsHandler,
        Exception exception
    ) {
        // no-op
    }

    private String extractToken(ServerHttpRequest request) {
        String query = request.getURI().getQuery();
        if (query == null) return null;

        for (String param : query.split("&")) {
            String[] kv = param.split("=", 2);
            if (kv.length == 2 && kv[0].equals("token")) {
                return URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
            }
        }
        return null;
    }
}
