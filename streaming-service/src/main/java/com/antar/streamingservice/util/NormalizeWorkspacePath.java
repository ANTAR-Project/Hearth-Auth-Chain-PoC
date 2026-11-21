package com.antar.streamingservice.util;

import com.antar.streamingservice.dto.PlaylistDto;

public final class NormalizeWorkspacePath {
    private NormalizeWorkspacePath() {
    }

    /**
     * Removes the leading "<username>/" workspace root. Null-safe; returns the input unchanged if the prefix is absent.
     */
    public static String stripWorkspaceRoot(String username, String path) {
        if (path == null) return null;
        String prefix = username + "/";
        return path.startsWith(prefix) ? path.substring(prefix.length()) : path;
    }

    /**
     * The client workspace view of a playlist (paths relative to user workspace root).
     */
    public static PlaylistDto toClientView(String username, String rawPath, String thumbnailPath) {
        return new PlaylistDto(
            stripWorkspaceRoot(username, rawPath),
            stripWorkspaceRoot(username, thumbnailPath)
        );
    }
}
