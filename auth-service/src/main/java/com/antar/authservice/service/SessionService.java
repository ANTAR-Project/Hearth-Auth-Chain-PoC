package com.antar.authservice.service;

import com.antar.authservice.event.DenylistPublisher;
import com.antar.authservice.model.Session;
import com.antar.authservice.model.User;
import com.antar.authservice.repository.SessionRepository;
import com.antar.authservice.security.AccessTokenIssuer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Service
public class SessionService {
    private final SessionRepository sessions;
    private final AccessTokenIssuer issuer;
    private final DenylistPublisher denylist;

    public SessionService(
        SessionRepository sessions,
        AccessTokenIssuer issuer,
        DenylistPublisher denylist
    ) {
        this.sessions = sessions;
        this.issuer = issuer;
        this.denylist = denylist;
    }

    @Transactional
    public TokenPair create(User u, String deviceId) {
        UUID sid = UUID.randomUUID();
        String rawRefresh = sid + "." + randomHex(32);

        Session s = new Session();
        s.setId(sid);
        s.setUser(u);
        s.setDeviceId(deviceId);
        s.setAmr(new String[]{"pwd"});
        s.setRefreshHash(sha256b64(rawRefresh));
        s.setExpiresAt(Instant.now().plus(Duration.ofDays(7)));
        sessions.save(s);

        return new TokenPair(issuer.issue(u, sid, List.of("pwd")), rawRefresh, 900);
    }

    @Transactional
    public TokenPair rotate(String presented) {
        int dot = presented.indexOf('.');
        if (dot < 0) throw new InvalidRefreshException();
        UUID sid;

        try {
            sid = UUID.fromString(presented.substring(0, dot));
        } catch (IllegalArgumentException e) {
            throw new InvalidRefreshException();
        }

        Session s = sessions.findByIdForUpdate(sid).orElseThrow(InvalidRefreshException::new);
        if (s.getRevokedAt() != null || s.getExpiresAt().isBefore(Instant.now()))
            throw new InvalidRefreshException();

        String h = sha256b64(presented);
        if (h.equals(s.getRefreshHash())) {
            String next = sid + "." + randomHex(32);
            s.setPrevRefreshHash(s.getRefreshHash());
            s.setRefreshHash(sha256b64(next));
            s.setLastUsedAt(Instant.now());
            sessions.save(s);
            return new TokenPair(issuer.issue(s.getUser(), sid, List.of(s.getAmr())), next, 900);
        }

        if (h.equals(s.getPrevRefreshHash())) {
            revoke(s, "REFRESH_REUSE");
        }
        throw new InvalidRefreshException();
    }

    @Transactional
    public void revoke(UUID sessionId, String reason) {
        sessions.findById(sessionId).ifPresent(s -> revoke(s, reason));
    }

    public void revoke(Session s, String reason) {
        s.setRevokedAt(Instant.now());
        s.setRevokedReason(reason);
        sessions.save(s);
        denylist.deny(s.getId().toString(), reason);
    }

    private static String sha256b64(String input) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String randomHex(int bytes) {
        byte[] b = new byte[bytes];
        new SecureRandom().nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    public record TokenPair(
        String accessToken,
        String refreshToken,
        long expiresIn
    ) {
    }

    public static class InvalidRefreshException extends RuntimeException {
        public InvalidRefreshException() {
            super("invalid refresh token");
        }
    }
}
