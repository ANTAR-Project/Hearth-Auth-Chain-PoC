package com.antar.authservice.dto;

import jakarta.validation.constraints.NotBlank;

public record ClientCredentialsRequest(
    @NotBlank String grantType,
    @NotBlank String clientId,
    @NotBlank String clientSecret,
    @NotBlank String audience,
    String scope
) {
}
