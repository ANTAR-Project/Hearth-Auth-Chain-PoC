package com.antar.apigateway.config;

import com.antar.hearth.common.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import java.net.URL;
import java.time.Duration;

@Configuration
public class GatewayAuthConfig {
    @Value("${hearth.auth.jwks-uri}")
    private String authJwksUri;

    @Bean
    public JwtVerifier accessTokenVerifier() throws Exception {
        DiskBackedJwkSource src = new DiskBackedJwkSource(new URL(authJwksUri), "hearth-auth");
        return new JwtVerifier(src,
                new JwtVerifier.Spec("at+jwt", "hearth-auth", "hearth-gateway", Duration.ofSeconds(5)));
    }
}