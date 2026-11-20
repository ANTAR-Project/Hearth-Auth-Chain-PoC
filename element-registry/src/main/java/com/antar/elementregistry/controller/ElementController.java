package com.antar.elementregistry.controller;

import com.antar.hearth.common.Hearth;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/internal/elements")
public class ElementController {

    @GetMapping("/{elementId}")
    public ResponseEntity<Map<String, Object>> get(
        @PathVariable String elementId, HttpServletRequest req) {
        if (req.getHeader(Hearth.CTX_HEADER) == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(Map.of("elementId", elementId,
            "type", "LIGHT", "qualifier", "LIGHT", "stub", true));
    }

    @PutMapping("/{elementId}/state")
    public ResponseEntity<Map<String, Object>> setState(
        @PathVariable String elementId,
        @RequestBody Map<String, Object> body, HttpServletRequest req) {
        if (req.getHeader(Hearth.CTX_HEADER) == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(Map.of("elementId", elementId, "applied", body, "stub", true));
    }
}