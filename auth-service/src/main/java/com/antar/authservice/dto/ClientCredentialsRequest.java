package com.antar.authservice.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record ClientCredentialsRequest(
    @NotBlank
    @JsonProperty("grant_type")
    @JsonAlias({"grantType", "grant_type"})
    String grantType,

    @NotBlank
    @JsonProperty("client_id")
    @JsonAlias({"clientId", "client_id"})
    String clientId,

    @NotBlank
    @JsonProperty("client_secret")
    @JsonAlias({"clientSecret", "client_secret"})
    String clientSecret,

    @NotBlank
    String audience,

    String scope
) {
}
