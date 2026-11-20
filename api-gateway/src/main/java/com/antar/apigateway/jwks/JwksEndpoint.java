package com.antar.apigateway.jwks;

import com.antar.apigateway.config.GatewayKeys;
import org.springframework.boot.actuate.endpoint.annotation.*;
import org.springframework.stereotype.Component;
import java.util.Map;

@Component
@WebEndpoint(id = "jwks")
public class JwksEndpoint {
    private final GatewayKeys keys;
    public JwksEndpoint(GatewayKeys keys) { this.keys = keys; }
    @ReadOperation
    public Map<String, Object> jwks() { return keys.publicJwkSet().toJSONObject(); }
}