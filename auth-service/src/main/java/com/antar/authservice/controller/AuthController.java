package com.antar.authservice.controller;

import com.antar.authservice.dto.LoginRequest;
import com.antar.authservice.dto.LoginResponse;
import com.antar.authservice.dto.RefreshRequest;
import com.antar.authservice.model.User;
import com.antar.authservice.repository.UserRepository;
import com.antar.authservice.service.SessionService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final UserRepository users;
    private final SessionService sessions;
    private final PasswordEncoder encoder;

    public AuthController(
        UserRepository users,
        SessionService sessions,
        PasswordEncoder encoder
    ) {
        this.users = users;
        this.sessions = sessions;
        this.encoder = encoder;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest req) {
        User u = users.findByUsername(req.username())
            .filter(found -> encoder.matches(req.password(), found.getPasswordHash()))
            .orElseThrow(() -> new AuthException("INVALID_CREDENTIALS", 401));

        if (u.getStatus() != User.UserStatus.ACTIVE)
            throw new AuthException("ACCOUNT_SUSPENDED", 403);
        if (u.getExpiresAt() != null && u.getExpiresAt().isBefore(Instant.now()))
            throw new AuthException("ACCOUNT_EXPIRED", 403);

        // Re-hash to Argon2 if still bcrypt
        if (encoder.upgradeEncoding(u.getPasswordHash())) {
            u.setPasswordHash(encoder.encode(req.password()));
            users.save(u);
        }

        SessionService.TokenPair pair = sessions.create(u, req.deviceId());
        return ResponseEntity.ok(new LoginResponse(pair.accessToken(), pair.refreshToken(), pair.expiresIn()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshRequest req) {
        SessionService.TokenPair pair = sessions.rotate(req.refreshToken());
        return ResponseEntity.ok(new LoginResponse(pair.accessToken(), pair.refreshToken(), pair.expiresIn()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("X-Session-Id") String sid) {
        sessions.revoke(UUID.fromString(sid), "LOGOUT");
        return ResponseEntity.noContent().build();
    }

    public static class AuthException extends RuntimeException {
        private final int status;

        public AuthException(String msg, int status) {
            super(msg);
            this.status = status;
        }

        public int getStatus() {
            return status;
        }
    }
}
