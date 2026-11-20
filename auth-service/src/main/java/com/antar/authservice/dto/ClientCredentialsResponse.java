package com.antar.authservice.dto;

public record ClientCredentialsResponse(
    String accessToken,
    long expiresIn,
    String tokenType,
    String scope
) {
}
