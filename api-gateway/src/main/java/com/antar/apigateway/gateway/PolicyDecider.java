package com.antar.apigateway.gateway;

import com.antar.hearth.common.Intent;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class PolicyDecider {

    public Intent.Decision decide(RouteMeta meta, Intent.Subject subject, ServerHttpRequest req) {
        String role = subject.role() != null ? subject.role().toUpperCase() : "GUEST";
        String action = meta.action() != null ? meta.action().toUpperCase() : req.getMethod().name();
        String domain = meta.domain() != null ? meta.domain().toUpperCase() : "NAS";
        String resType = meta.resourceType() != null ? meta.resourceType().toUpperCase() : "WORKSPACE";
        String namespace = meta.namespace() != null ? meta.namespace().toUpperCase() : "OWN";
        String intent = meta.intent() != null ? meta.intent().toLowerCase() : "";

        // 1. OWNER has full unrestricted access
        if ("OWNER".equals(role)) {
            return new Intent.Decision("ALLOW", "ANY");
        }

        // 2. RESIDENT policy
        if ("RESIDENT".equals(role)) {
            // Workspace permanent deletion is OWNER only (RESIDENT can only clear)
            if ("DELETE".equals(action) && ("nas.workspace.delete".equals(intent) || "WORKSPACE".equals(resType) && intent.contains("delete"))) {
                return new Intent.Decision("DENY", null);
            }

            // Cross-user access check: cannot access another user's private workspace
            String requestedUser = req.getQueryParams().getFirst("user");
            if (requestedUser == null) {
                requestedUser = req.getQueryParams().getFirst("username");
            }
            if (requestedUser != null && !requestedUser.equalsIgnoreCase(subject.username())) {
                return new Intent.Decision("DENY", null);
            }

            // Shared namespace
            if ("SHARED".equals(namespace) || "SHARED".equals(resType) || intent.contains("shared")) {
                return new Intent.Decision("ALLOW", "SHARED");
            }

            // Elements and media streaming
            if ("ELEMENT".equals(domain) || "MEDIA".equals(resType) || "STREAM".equals(action)) {
                return new Intent.Decision("ALLOW", "ANY");
            }

            // Private workspace / own files
            if ("OWN".equals(namespace) || "WORKSPACE".equals(resType) || intent.startsWith("nas.")) {
                return new Intent.Decision("ALLOW", "OWN");
            }

            return new Intent.Decision("ALLOW", "OWN");
        }

        // 3. GUEST policy
        if ("GUEST".equals(role)) {
            // Element camera deny
            if ("CAMERA".equalsIgnoreCase(meta.qualifier()) || intent.contains("camera")) {
                return new Intent.Decision("DENY", null);
            }

            // Element read is allowed
            if ("ELEMENT".equals(domain) && ("READ".equals(action) || "LIST".equals(action) || "GET".equals(action))) {
                return new Intent.Decision("ALLOW", "ANY");
            }

            // Shared workspace read is allowed
            if (("SHARED".equals(namespace) || "SHARED".equals(resType) || intent.contains("shared"))
                    && ("READ".equals(action) || "LIST".equals(action) || "GET".equals(action))) {
                return new Intent.Decision("ALLOW", "SHARED");
            }

            // All other GUEST actions (write, update, delete, own workspace, video upload, element control) are denied
            return new Intent.Decision("DENY", null);
        }

        return new Intent.Decision("DENY", null);
    }
}
