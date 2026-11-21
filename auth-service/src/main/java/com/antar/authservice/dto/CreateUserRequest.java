package com.antar.authservice.dto;

import com.antar.authservice.model.User;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public record CreateUserRequest(
    @NotBlank(message = "Username is required")
    @Pattern(regexp = "^[a-z0-9_-]{3,32}$", message = "Username must be 3-32 characters: lowercase, digits, _, -")
    String username,

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    String password,

    @NotNull(message = "Role is required")
    User.UserRole role,

    Instant expiresAt,

    Boolean mustChangePassword
) {
}
