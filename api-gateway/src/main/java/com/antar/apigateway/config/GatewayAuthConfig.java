package com.antar.apigateway.config;

import com.antar.hearth.common.DiskBackedJwkSource;
import com.antar.hearth.common.Hearth;
import com.antar.hearth.common.JwtVerifier;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URL;
import java.time.Duration;

@Configuration
public class GatewayAuthConfig {
    private static final Logger log = LoggerFactory.getLogger(GatewayAuthConfig.class);

    @Value("${hearth.auth.jwks-uri}")
    private String authJwksUri;

    @Bean
    public DiskBackedJwkSource authJwkSource() throws Exception {
        return new DiskBackedJwkSource(new URL(authJwksUri), "hearth-auth");
    }

    @Bean
    public JwtVerifier accessTokenVerifier(DiskBackedJwkSource authJwkSource) {
        return new JwtVerifier(authJwkSource,
                new JwtVerifier.Spec(Hearth.TYP_ACCESS, Hearth.ISS_AUTH, "hearth-gateway", Duration.ofSeconds(5)));
    }

    @Bean
    public ApplicationRunner jwksWarmup(DiskBackedJwkSource authJwkSource) {
        return args -> {
            Thread.ofVirtual().start(() -> {
                for (int attempt = 1; attempt <= 10; attempt++) {
                    try {
                        Thread.sleep(attempt == 1 ? 2000 : 3000);
                        authJwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
                        log.info("Successfully warmed up auth JWKS cache from {}", authJwksUri);
                        return;
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return;
                    } catch (Exception e) {
                        if (attempt == 10) {
                            log.warn("Initial JWKS warm-up from {} failed after {} attempts (will retry on request): {}",
                                    authJwksUri, attempt, e.getMessage());
                        } else {
                            log.debug("Warm-up attempt {}/10 for {} pending auth-service readiness: {}",
                                    attempt, authJwksUri, e.getMessage());
                        }
                    }
                }
            });
        };
    }
}
