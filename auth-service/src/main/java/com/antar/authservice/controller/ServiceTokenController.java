package com.antar.authservice.controller;

import com.antar.authservice.dto.ClientCredentialsRequest;
import com.antar.authservice.dto.ClientCredentialsResponse;
import com.antar.authservice.model.ServiceClient;
import com.antar.authservice.repository.ServiceClientRepository;
import com.antar.authservice.security.AccessTokenIssuer;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

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

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> tokenJson(@Valid @RequestBody ClientCredentialsRequest req) {
        return processToken(req);
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> tokenForm(
        @RequestParam(name = "grant_type", required = false) String grantTypeParam,
        @RequestParam(name = "grantType", required = false) String grantTypeAlt,
        @RequestParam(name = "client_id", required = false) String clientIdParam,
        @RequestParam(name = "clientId", required = false) String clientIdAlt,
        @RequestParam(name = "client_secret", required = false) String clientSecretParam,
        @RequestParam(name = "clientSecret", required = false) String clientSecretAlt,
        @RequestParam(name = "audience", required = false) String audience,
        @RequestParam(name = "scope", required = false) String scope
    ) {
        String grantType = grantTypeParam != null ? grantTypeParam : grantTypeAlt;
        String clientId = clientIdParam != null ? clientIdParam : clientIdAlt;
        String clientSecret = clientSecretParam != null ? clientSecretParam : clientSecretAlt;
        return processToken(new ClientCredentialsRequest(grantType, clientId, clientSecret, audience, scope));
    }

    private ResponseEntity<?> processToken(ClientCredentialsRequest req) {
        if (!"client_credentials".equals(req.grantType()))
            return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));

        if (req.clientId() == null || req.clientSecret() == null || req.audience() == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_request", "detail", "missing required fields"));
        }

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
