package com.antar.hearth.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Shared bind computation. Gateway and all domain services must use this exact class.
 * Golden test vectors: bind-vectors.json in src/test/resources.
 */
public final class BindCalculator {
    private static final ObjectMapper CANON = JsonMapper.builder()
        .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
        .build();

    private BindCalculator() {
    }

    /**
     * @param method   HTTP method (or "GRPC"), upper-cased
     * @param rawPath  percent-encoded path as the upstream service will receive it
     * @param rawQuery raw query string (maybe null)
     * @param checksum value of X-Checksum-SHA256 header (maybe null)
     * @param jsonBody bounded JSON body bytes, or null/empty for streamed bodies
     */
    public static String bind(
        String method,
        String rawPath,
        String rawQuery,
        String checksum,
        byte[] jsonBody
    ) {
        String body = (jsonBody == null || jsonBody.length == 0) ? "" : hex(
            sha256(canonicalJson(jsonBody))
        );

        String canonical = String.join("\n",
            method.toUpperCase(),
            rawPath,
            sortedQuery(rawQuery),
            checksum == null ? "" : checksum.toLowerCase(),
            body);

        return Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(sha256(
                canonical.getBytes(StandardCharsets.UTF_8)
            ));
    }

    static String sortedQuery(String rawQuery) {
        if (rawQuery == null || rawQuery.isEmpty()) return "";

        String[] parts = rawQuery.split("&");
        Arrays.sort(parts);

        return String.join("&", parts);
    }

    static byte[] canonicalJson(byte[] raw) {
        try {
            return CANON.writeValueAsBytes(CANON.readValue(raw, Object.class));
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid json body: ", e);
        }
    }

    static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);

        for (byte v : b) {
            sb.append(String.format("%02x", v));
        }

        return sb.toString();
    }
}
