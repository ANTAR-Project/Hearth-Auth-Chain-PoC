package com.antar.apigateway.gateway;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * RFC 9457 (Problem Details for HTTP APIs) writer for Spring Cloud Gateway (WebFlux).
 */
public final class Problems {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Problems() {
    }

    public static Mono<Void> write(ServerWebExchange ex, int status, String code) {
        ServerHttpResponse res = ex.getResponse();
        res.setStatusCode(HttpStatusCode.valueOf(status));
        res.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "about:blank");
        body.put("title", code.replace('_', ' ').toLowerCase());
        body.put("status", status);
        body.put("code", code);

        String intentId = ex.getAttribute("hearth.intentId");
        if (intentId != null) {
            body.put("intentId", intentId);
        }

        byte[] bytes;
        try {
            bytes = MAPPER.writeValueAsBytes(body);
        } catch (JsonProcessingException e) {
            bytes = ("{\"status\":" + status + ",\"code\":\"" + code + "\"}").getBytes(StandardCharsets.UTF_8);
        }

        DataBuffer buffer = res.bufferFactory().wrap(bytes);
        return res.writeWith(Mono.just(buffer));
    }
}
