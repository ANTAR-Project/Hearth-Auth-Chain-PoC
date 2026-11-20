package com.antar.nasorchestrator.hearth;

import com.antar.hearth.common.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import java.net.URL;
import java.time.Duration;

@Configuration
public class NasHearthConfig {
    @Value("${hearth.gateway.jwks-uri:http://api-gateway:8081/internal/jwks}")
    private String gatewayJwksUri;
    @Value("${spring.application.name:nas-orchestrator}")
    private String selfName;

    @Bean
    public JwtVerifier contextTokenVerifier() throws Exception {
        DiskBackedJwkSource src = new DiskBackedJwkSource(new URL(gatewayJwksUri), "hearth-gateway");
        return new JwtVerifier(src,
                new JwtVerifier.Spec(Hearth.TYP_CTX, Hearth.ISS_GATEWAY, selfName, Duration.ofSeconds(5)));
    }
}