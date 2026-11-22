package com.antar.authservice.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Component
public class AuthKeys {
    private static final Logger log = LoggerFactory.getLogger(AuthKeys.class);

    @Value("${auth.keys.dir}")
    private String keysDir;
    @Value("${auth.keys.current-kid}")
    private String currentKid;

    private final Map<String, ECKey> keyMap = new LinkedHashMap<>();
    private ECKey currentKey;

    @PostConstruct
    public void load() throws Exception {
        Path dir = Path.of(keysDir);

        if (!Files.isDirectory(dir)) {
            log.warn("auth.keys.dir not found — generating ephemeral in-memory key (dev only)");

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
                    log.info("Loaded auth key: {}", kid);
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to load auth key " + p, e);
                }
            });
        }

        currentKey = Objects.requireNonNull(keyMap.get(currentKid),
            "auth.keys.current-kid=" + currentKid + " not found in " + keysDir);
    }

    public String sign(JWTClaimsSet claims, String typ) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(currentKey.getKeyID())
            .type(new JOSEObjectType(typ))
            .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(currentKey));
        return jwt.serialize();
    }

    public JWKSet publicJwkSet() {
        List<JWK> pubs = keyMap.values().stream().map(k -> (JWK) k.toPublicJWK()).toList();
        return new JWKSet(pubs);
    }

    public ECKey current() {
        return currentKey;
    }

    public ECKey getKey(String kid) {
        if (kid != null && keyMap.containsKey(kid)) {
            return keyMap.get(kid);
        }
        return currentKey;
    }
}
