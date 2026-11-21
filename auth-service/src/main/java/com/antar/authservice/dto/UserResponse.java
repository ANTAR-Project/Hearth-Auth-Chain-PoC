package com.antar.authservice.dto;

import com.antar.authservice.model.User;

import java.time.Instant;
import java.util.UUID;

public record UserResponse(
    UUID id,
    String username,
    User.UserRole role,
    User.UserStatus status,
    boolean mustChangePassword,
    Instant expiresAt,
    Instant createdAt
) {
    public static UserResponse from(User u) {
        return new UserResponse(
            u.getId(),
            u.getUsername(),
            u.getRole(),
            u.getStatus(),
            u.isMustChangePassword(),
            u.getExpiresAt(),
            u.getCreatedAt()
        );
    }
}
