package com.antar.hearth.common;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Wraps a Nimbus JWKSource with disk-persisted fallback.
 * On every successful fetch, merges keys by kid and writes atomically to
 * /var/hearth/jwks/{issuer-name}.json.
 * On KeySourceException, serves lastKnown, loading the file if memory is cold.
 */
public final class DiskBackedJwkSource implements JWKSource<SecurityContext> {
    private static final Logger log = LoggerFactory.getLogger(DiskBackedJwkSource.class);

    private final JWKSource<SecurityContext> delegate;
    private final Path cacheFile;
    private final List<JWK> lastKnown = new CopyOnWriteArrayList<>();

    public DiskBackedJwkSource(
        URL jwksUrl,
        String issuerName
    ) {
        this.delegate = JWKSourceBuilder.create(jwksUrl)
            .retrying(true)
            .rateLimited(30_000)
            .build();

        Path dir = Path.of("/var/hearth/jwks");
        try {
            Files.createDirectories(dir);
        } catch (IOException ignored) {
        }

        this.cacheFile = dir.resolve(issuerName + ".json");
    }

    @Override
    public List<JWK> get(JWKSelector selector, SecurityContext ctx) throws KeySourceException {
        try {
            List<JWK> fresh = delegate.get(selector, ctx);
            mergeAndPersist(fresh);

            return fresh;
        } catch (KeySourceException e) {
            log.warn("JWKS fetch failed, serving cached keys: {}", e.getMessage());

            if (lastKnown.isEmpty()) loadFromDisk();
            List<JWK> matching = selector.select(new JWKSet(lastKnown));
            if (matching.isEmpty()) throw e;

            return matching;
        }
    }

    private synchronized void mergeAndPersist(List<JWK> fresh) {
        Map<String, JWK> byKid = new LinkedHashMap<>();

        lastKnown.forEach(k -> byKid.put(k.getKeyID(), k));
        fresh.forEach(k -> byKid.put(k.getKeyID(), k));
        lastKnown.clear();
        lastKnown.addAll(byKid.values());

        try {
            Path tmp = cacheFile.resolveSibling(cacheFile.getFileName() + ".tmp");
            String json = new JWKSet(lastKnown).toString(false);

            Files.writeString(tmp, json, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(tmp, cacheFile, StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException ex) {
            log.warn("Could not persist JWKS cache: {}", ex.getMessage());
        }
    }

    private synchronized void loadFromDisk() {
        try {
            if (Files.exists(cacheFile)) {
                String json = Files.readString(cacheFile);
                JWKSet set = JWKSet.parse(json);

                lastKnown.addAll(set.getKeys());
                log.info("Loaded {} JWKS keys from disk cache {}", lastKnown.size(), cacheFile);
            }
        } catch (IOException | ParseException ex) {
            log.error("Could not load JWKS disk cache: {}", ex.getMessage());
        }
    }
}
