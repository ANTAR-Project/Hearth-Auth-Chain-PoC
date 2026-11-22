package com.antar.authservice.controller;

import com.antar.authservice.controller.AuthController.AuthException;
import com.antar.authservice.service.SessionService.InvalidRefreshException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;

@RestControllerAdvice
public class AuthExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex) {
        return ResponseEntity.status(ex.getStatus())
            .body(Map.of(
                "error", ex.getMessage(),
                "status", ex.getStatus(),
                "timestamp", Instant.now().toString()
            ));
    }

    @ExceptionHandler(InvalidRefreshException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidRefresh(InvalidRefreshException ex) {
        return ResponseEntity.status(401)
            .body(Map.of(
                "error", "INVALID_REFRESH_TOKEN",
                "status", 401,
                "timestamp", Instant.now().toString()
            ));
    }
}
