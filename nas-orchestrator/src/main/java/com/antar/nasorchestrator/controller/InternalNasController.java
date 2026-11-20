package com.antar.nasorchestrator.controller;

import com.antar.hearth.common.ScopeEnforcer;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;

import java.util.*;

@RestController
@RequestMapping("/internal/nas")
public class InternalNasController {
    private final WorkspaceAccess workspaceAccess;

    public InternalNasController(WorkspaceAccess workspaceAccess) {
        this.workspaceAccess = workspaceAccess;
    }

    @GetMapping("/files/list")
    public ResponseEntity<?> listFiles(@RequestParam(defaultValue = "") String path, HttpServletRequest req) {
        HearthPrincipal p = principal(req);
        var resolved = workspaceAccess.resolve(p, path);
        // ... call existing FileService with resolved path
        return ResponseEntity.ok(Map.of("path", resolved.toString(), "files", List.of()));
    }

    @GetMapping("/files/**")
    public ResponseEntity<?> readFile(HttpServletRequest req) {
        HearthPrincipal p = principal(req);
        String path = req.getRequestURI().replaceFirst("/internal/nas/files", "");
        var resolved = workspaceAccess.resolve(p, path);
        // ... stream from NAS
        return ResponseEntity.ok().build();
    }

    @PutMapping("/files/**")
    public ResponseEntity<?> createFile(HttpServletRequest req) {
        HearthPrincipal p = principal(req);
        String path = req.getRequestURI().replaceFirst("/internal/nas/files", "");
        var resolved = workspaceAccess.resolve(p, path);
        // ... stream request body to NAS, verify SHA256
        return ResponseEntity.status(201).build();
    }

    @PostMapping("/uploads")
    public ResponseEntity<Map<String, Object>> initUpload(@RequestParam String path, HttpServletRequest req) {
        HearthPrincipal p = principal(req);
        workspaceAccess.resolve(p, path);  // scope + traversal check
        String uploadId = "u-" + UUID.randomUUID().toString().substring(0, 8);
        return ResponseEntity.ok(Map.of("uploadId", uploadId));
    }

    @ExceptionHandler(ScopeEnforcer.ScopeViolation.class)
    public ResponseEntity<?> handleScopeViolation(ScopeEnforcer.ScopeViolation e) {
        return ResponseEntity.status(403)
                .body(Map.of("status", 403, "code", "SCOPE_VIOLATION", "detail", e.getMessage()));
    }

    private HearthPrincipal principal(HttpServletRequest req) {
        HearthPrincipal p = (HearthPrincipal) req.getAttribute(HearthPrincipal.ATTR);
        if (p == null) throw new IllegalStateException("No HearthPrincipal — ContextTokenFilter not applied");
        return p;
    }
}