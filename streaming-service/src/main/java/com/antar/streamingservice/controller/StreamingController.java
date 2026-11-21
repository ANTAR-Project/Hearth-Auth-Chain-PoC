package com.antar.streamingservice.controller;

import com.antar.hearth.common.ScopeEnforcer;
import com.antar.streamingservice.config.ServiceTokenRefresher;
import com.antar.streamingservice.dto.PlaylistDto;
import com.antar.streamingservice.hearth.HearthPrincipal;
import com.antar.streamingservice.service.PlaylistService;
import com.antar.streamingservice.service.StreamingService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@Slf4j
@Validated
@RequestMapping("/api/v1/stream")
public class StreamingController {
    private static final String MASTER_PLAYLIST_KEY_PREFIX = "streaming:playlist:";

    private final StreamingService streamingService;
    private final PlaylistService playlistService;
    private final ServiceTokenRefresher serviceTokenRefresher;
    private final RedisTemplate<String, String> redisTemplate;

    private HearthPrincipal principal(HttpServletRequest request) {
        HearthPrincipal p = (HearthPrincipal) request.getAttribute(HearthPrincipal.ATTR);
        if (p == null) throw new IllegalStateException("Missing HearthPrincipal — ContextTokenFilter did not run");
        ScopeEnforcer.of(p.scope()).enforce(p.username(), p.resourceId(), p.namespace());
        return p;
    }

    /**
     * Resolves the movie's NAS-relative playlist path from Redis, then proxies the raw M3U8 content through from nas-orchestrator.
     * Segment requests are NOT routed through streaming-service — the playlist
     * returned by nas-orchestrator already rewrites segment URIs to point
     * directly at /api/v1/nas-orchestrator/stream/segment, so the client
     * fetches segments without touching this service again.
     */
    @GetMapping("")
    public ResponseEntity<String> getPlaylist(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path
    ) {
        HearthPrincipal p = principal(request);
        String scopedPath = path.isEmpty() ? p.resourceId() : p.resourceId() + "/" + path;
        log.info("Playlist request from {} for movieId: {}", p.username(), scopedPath);

        String playlistPath = redisTemplate.opsForValue().get(MASTER_PLAYLIST_KEY_PREFIX + scopedPath);
        if (playlistPath == null) {
            log.warn("No playlist registered for movieId: {}", scopedPath);
            return ResponseEntity.notFound().build();
        }

        String token = resolveStreamingToken(request);

        log.info("Proxying playlist for movieId: {} at path: {}", scopedPath, playlistPath);
        return ResponseEntity.ok()
            .header("Content-Type", "application/x-mpegURL")
            .body(streamingService.getPlaylist(playlistPath, token));
    }

    @GetMapping("/playlists")
    public ResponseEntity<List<PlaylistDto>> getUserPlaylists(HttpServletRequest request) {
        HearthPrincipal p = principal(request);
        List<PlaylistDto> playLists = playlistService.getPlaylistsForUser(p.resourceId());

        return ResponseEntity.ok(playLists);
    }

    private String resolveStreamingToken(HttpServletRequest request) {
        String tokenParam = request.getParameter("token");
        if (tokenParam != null && !tokenParam.isBlank()) {
            return tokenParam;
        }
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        try {
            return serviceTokenRefresher.get();
        } catch (Exception e) {
            log.warn("Could not obtain service token for streaming playlist proxying: {}", e.getMessage());
            return "";
        }
    }
}
