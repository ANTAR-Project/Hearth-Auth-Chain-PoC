package com.antar.elementregistry.controller;

import com.antar.elementregistry.hearth.HearthPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/elements")
public class ElementController {

    private HearthPrincipal principal(HttpServletRequest req) {
        HearthPrincipal p = (HearthPrincipal) req.getAttribute(HearthPrincipal.ATTR);
        if (p == null) throw new IllegalStateException("Missing HearthPrincipal — ContextTokenFilter did not run");
        return p;
    }

    @GetMapping("/{elementId}")
    public ResponseEntity<Map<String, Object>> get(
        @PathVariable String elementId, HttpServletRequest req) {
        HearthPrincipal p = principal(req);
        return ResponseEntity.ok(Map.of(
            "elementId", elementId,
            "requestedBy", p.username(),
            "type", "LIGHT",
            "qualifier", "LIGHT",
            "stub", true));
    }

    @PutMapping("/{elementId}/state")
    public ResponseEntity<Map<String, Object>> setState(
        @PathVariable String elementId,
        @RequestBody Map<String, Object> body,
        HttpServletRequest req) {
        HearthPrincipal p = principal(req);
        return ResponseEntity.ok(Map.of(
            "elementId", elementId,
            "appliedBy", p.username(),
            "applied", body,
            "stub", true));
    }
}
