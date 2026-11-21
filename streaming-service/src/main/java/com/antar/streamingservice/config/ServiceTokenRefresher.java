package com.antar.streamingservice.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import static java.nio.charset.StandardCharsets.UTF_8;

@Component
public class ServiceTokenRefresher {
    private static final Logger log = LoggerFactory.getLogger(ServiceTokenRefresher.class);

    @Value("${auth.service.url}")
    private String authUrl;

    @Value("${auth.client.id}")
    private String clientId;

    @Value("${auth.client.secret}")
    private String clientSecret;

    @Value("${auth.client.audience}")
    private String audience;

    @Value("${auth.client.scope}")
    private String scope;

    private final AtomicReference<String> currentToken = new AtomicReference<String>();
    private volatile Instant refreshAt = Instant.MIN;
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();

    @PostConstruct
    public void init() {
        refresh();
    }

    @Scheduled(fixedDelay = 10_000)
    public void maybeRefresh() {
        if (Instant.now().isAfter(refreshAt)) {
            refresh();
        }
    }

    private synchronized void refresh() {
        try {
            String body = "grant_type=client_credentials"
                + "&client_id=" + URLEncoder.encode(clientId, UTF_8)
                + "&client_secret=" + URLEncoder.encode(clientSecret, UTF_8)
                + "&audience=" + URLEncoder.encode(audience, UTF_8)
                + "&scope=" + URLEncoder.encode(scope, UTF_8);

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(authUrl + "/oauth/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            JsonNode node = json.readTree(response.body());

            currentToken.set(node.get("accessToken").asText());
            long expiresIn = node.get("expiresIn").asLong(600);
            refreshAt = Instant.now().plusSeconds(expiresIn - 60);

            log.info("Service token refreshed for {}", clientId);
        } catch (IOException | InterruptedException e) {
            log.error("Service token refresh failed: {}", e.getMessage());
        }
    }

    public String get() {
        String token = currentToken.get();

        if (token == null) {
            throw new IllegalStateException("No service token available yet");
        }

        return token;
    }
}
