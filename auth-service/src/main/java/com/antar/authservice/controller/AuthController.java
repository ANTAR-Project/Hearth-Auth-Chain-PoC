package com.antar.authservice.controller;

import com.antar.authservice.config.AuthKeys;
import com.antar.authservice.dto.*;
import com.antar.authservice.model.User;
import com.antar.authservice.repository.UserRepository;
import com.antar.authservice.service.SessionService;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final UserRepository users;
    private final SessionService sessions;
    private final PasswordEncoder encoder;
    private final AuthKeys authKeys;

    public AuthController(
        UserRepository users,
        SessionService sessions,
        PasswordEncoder encoder,
        AuthKeys authKeys
    ) {
        this.users = users;
        this.sessions = sessions;
        this.encoder = encoder;
        this.authKeys = authKeys;
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

    /**
     * Endpoint where an OWNER can create a RESIDENT or GUEST user.
     * Enforces caller has role == OWNER via Authorization Bearer token.
     */
    @PostMapping("/users")
    public ResponseEntity<UserResponse> createUser(
        @RequestHeader(value = "Authorization", required = false) String authHeader,
        @Valid @RequestBody CreateUserRequest req
    ) {
        assertOwner(authHeader);

        if (req.role() == User.UserRole.OWNER) {
            throw new AuthException("CANNOT_CREATE_OWNER_ROLE", 400);
        }

        if (users.findByUsername(req.username()).isPresent()) {
            throw new AuthException("USERNAME_ALREADY_EXISTS", 409);
        }

        User u = new User();
        u.setUsername(req.username());
        u.setPasswordHash(encoder.encode(req.password()));
        u.setRole(req.role());
        u.setStatus(User.UserStatus.ACTIVE);
        u.setMustChangePassword(req.mustChangePassword() != null ? req.mustChangePassword() : false);
        u.setExpiresAt(req.expiresAt());

        User saved = users.save(u);
        return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.from(saved));
    }

    /**
     * Endpoint for an OWNER to list all registered users.
     */
    @GetMapping("/users")
    public ResponseEntity<List<UserResponse>> listUsers(
        @RequestHeader(value = "Authorization", required = false) String authHeader
    ) {
        assertOwner(authHeader);
        List<UserResponse> list = users.findAll().stream()
            .map(UserResponse::from)
            .toList();
        return ResponseEntity.ok(list);
    }

    private void assertOwner(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthException("UNAUTHORIZED", 401);
        }
        String token = authHeader.substring(7).trim();
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            String kid = jwt.getHeader().getKeyID();
            var key = authKeys.getKey(kid);
            if (key == null || !jwt.verify(new ECDSAVerifier(key.toECPublicKey()))) {
                throw new AuthException("INVALID_TOKEN", 401);
            }

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Date exp = claims.getExpirationTime();
            if (exp != null && exp.before(new Date())) {
                throw new AuthException("TOKEN_EXPIRED", 401);
            }

            String role = claims.getStringClaim("role");
            if (!"OWNER".equals(role)) {
                throw new AuthException("FORBIDDEN_OWNER_REQUIRED", 403);
            }
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthException("INVALID_TOKEN: " + e.getMessage(), 401);
        }
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
