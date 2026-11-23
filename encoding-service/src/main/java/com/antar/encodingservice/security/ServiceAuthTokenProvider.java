package com.antar.encodingservice.security;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import com.antar.encodingservice.dto.*;

@Component
public class ServiceAuthTokenProvider {
    private static final Logger log = LoggerFactory.getLogger(ServiceAuthTokenProvider.class);

    private final RestClient authServiceRestClient;
    private final String serviceUsername;
    private final String serviceUsernamePassword;
    private volatile String token;

    public ServiceAuthTokenProvider(
        RestClient authServiceRestClient,
        @Value("${service.auth.username}") String serviceUsername,
        @Value("${service.auth.password}") String serviceUsernamePassword
    ) {
        this.authServiceRestClient = authServiceRestClient;
        this.serviceUsername = serviceUsername;
        this.serviceUsernamePassword = serviceUsernamePassword;
    }

    @PostConstruct
    public void registerAtStartup() {
        try {
            fetchAndCacheToken();
        } catch (Exception e) {
            log.warn("Could not obtain auth token at startup for '{}' — will retry lazily: {}", serviceUsername, e.getMessage());
        }
    }

    public String getToken() {
        if (token == null) {
            fetchAndCacheToken();
        }
        return token;
    }

    private synchronized void fetchAndCacheToken() {
        if (token != null) {
            return;
        }

        try {
            JsonNode node = authServiceRestClient.post()
                .uri("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .body(new TokenRequest(serviceUsername, serviceUsernamePassword))
                .retrieve()
                .body(JsonNode.class);

            if (node != null) {
                if (node.has("accessToken")) {
                    this.token = node.get("accessToken").asText();
                } else if (node.has("token")) {
                    this.token = node.get("token").asText();
                }
            }
            log.info("Registered service identity '{}' with auth-service", serviceUsername);
        } catch (Exception e) {
            log.warn("Could not fetch token via login endpoint: {}", e.getMessage());
        }
    }
}

