package com.antar.notificationservice.config;

import com.antar.hearth.common.DiskBackedJwkSource;
import com.antar.hearth.common.Hearth;
import com.antar.hearth.common.JwtVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URL;
import java.time.Duration;

@Configuration
public class NotificationHearthConfig {

    /**
     * Verifies the user's access token (ES256, issued by auth-service).
     * WebSocket handshake cannot carry a full HEARTH context token —
     * the browser passes the access token as ?token= query param instead.
     */
    @Bean
    public JwtVerifier accessTokenVerifier(
        @Value("${hearth.auth.jwks-uri}") String jwksUri
    ) throws Exception {
        DiskBackedJwkSource src = new DiskBackedJwkSource(new URL(jwksUri), "hearth-auth");
        return new JwtVerifier(src,
            new JwtVerifier.Spec(Hearth.TYP_ACCESS, Hearth.ISS_AUTH, null, Duration.ofSeconds(10)));
    }
}
