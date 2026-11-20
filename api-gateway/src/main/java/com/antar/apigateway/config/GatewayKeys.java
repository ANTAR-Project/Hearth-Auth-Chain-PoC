package com.antar.apigateway.config;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Component
public class GatewayKeys {
    private static final Logger log = LoggerFactory.getLogger(GatewayKeys.class);

    @Value("${hearth.gateway.keys-dir}")
    private String keysDir;

    @Value("${hearth.gateway.current-kid}")
    private String currentKid;

    private final Map<String, ECKey> keyMap = new LinkedHashMap<>();
    private ECKey currentKey;

    @PostConstruct
    public void load() throws Exception {
        Path dir = Path.of(keysDir);

        if (!Files.isDirectory(dir)) {
            log.warn("hearth.gateway.keys-dir not found — generating ephemeral in-memory gateway key (dev only)");

            ECKey k = new ECKeyGenerator(Curve.P_256).keyID(currentKid).generate();
            keyMap.put(currentKid, k);
            currentKey = k;
            return;
        }

        try (var stream = Files.list(dir)) {
            stream.filter(p -> p.toString().endsWith(".pem")).forEach(p -> {
                try {
                    String kid = p.getFileName().toString().replace(".pem", "");
                    String pem = Files.readString(p, StandardCharsets.UTF_8);
                    ECKey k = JWK.parseFromPEMEncodedObjects(pem).toECKey();
                    keyMap.put(kid, k);
                    log.info("Loaded gateway key: {}", kid);
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to load gateway key " + p, e);
                }
            });
        }

        currentKey = Objects.requireNonNull(keyMap.get(currentKid),
            "hearth.gateway.current-kid=" + currentKid + " not found in " + keysDir);
    }

    public JWKSet publicJwkSet() {
        List<JWK> pubs = keyMap.values().stream().map(k -> (JWK) k.toPublicJWK()).toList();
        return new JWKSet(pubs);
    }

    public ECKey current() {
        return currentKey;
    }
}
