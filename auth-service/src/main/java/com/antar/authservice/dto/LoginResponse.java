package com.antar.authservice.dto;

public record LoginResponse(
    String accessToken,
    String refreshToken,
    long expiresIn
) {
}
