package com.antar.authservice.controller;

import com.antar.authservice.dto.ClientCredentialsRequest;
import com.antar.authservice.dto.ClientCredentialsResponse;
import com.antar.authservice.model.ServiceClient;
import com.antar.authservice.repository.ServiceClientRepository;
import com.antar.authservice.security.AccessTokenIssuer;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/oauth")
public class ServiceTokenController {
    private final ServiceClientRepository clients;
    private final PasswordEncoder encoder;
    private final AccessTokenIssuer issuer;

    public ServiceTokenController(
        ServiceClientRepository clients,
        PasswordEncoder encoder,
        AccessTokenIssuer issuer
    ) {
        this.clients = clients;
        this.encoder = encoder;
        this.issuer = issuer;
    }

    @PostMapping("/token")
    public ResponseEntity<?> token(@Valid @RequestBody ClientCredentialsRequest req) {
        if (!"client_credentials".equals(req.grantType()))
            return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));

        ServiceClient c = clients.findByClientIdAndAudience(req.clientId(), req.audience())
            .orElseThrow(() -> new AuthController.AuthException("INVALID_CLIENT", 401));

        if (!c.isEnabled()) throw new AuthController.AuthException("CLIENT_DISABLED", 401);
        if (!encoder.matches(req.clientSecret(), c.getSecretHash()))
            throw new AuthController.AuthException("INVALID_CLIENT", 401);

        // Validate scope is a subset of allowed
        Set<String> allowedSet = Set.of(c.getScope().split(" "));
        if (req.scope() != null) {
            for (String s : req.scope().split(" ")) {
                if (!s.isBlank() && !allowedSet.contains(s))
                    return ResponseEntity.badRequest()
                        .body(Map.of("error", "invalid_scope", "detail", s));
            }
        }

        String effectiveScope = req.scope() != null ? req.scope() : c.getScope();
        String token = issuer.issueService(req.clientId(), req.audience(), effectiveScope);

        return ResponseEntity.ok(new ClientCredentialsResponse(token, 600, "Bearer", effectiveScope));
    }
}
