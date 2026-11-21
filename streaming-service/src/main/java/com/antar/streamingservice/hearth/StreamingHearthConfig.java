package com.antar.streamingservice.hearth;

import com.antar.hearth.common.DiskBackedJwkSource;
import com.antar.hearth.common.Hearth;
import com.antar.hearth.common.JwtVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URL;
import java.time.Duration;

@Configuration
public class StreamingHearthConfig {
    @Value("${hearth.gateway.jwks-uri}")
    private String gatewayJwksUri;
    @Value("${spring.application.name:streaming-service}")
    private String selfName;

    @Bean
    public JwtVerifier contextTokenVerifier() throws Exception {
        DiskBackedJwkSource src = new DiskBackedJwkSource(new URL(gatewayJwksUri), "hearth-gateway");
        return new JwtVerifier(src,
            new JwtVerifier.Spec(Hearth.TYP_CTX, Hearth.ISS_GATEWAY, selfName, Duration.ofSeconds(5)));
    }
}
