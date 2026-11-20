package com.antar.nasorchestrator.hearth;

import com.antar.hearth.common.ScopeEnforcer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;

@Component
public class WorkspaceAccess {
    private final Path workspacesRoot;

    public WorkspaceAccess(@Value("${hearth.nas.workspaces-root}") String root) {
        this.workspacesRoot = Path.of(root);
    }

    public Path resolve(HearthPrincipal p, String relativePath) {
        enforceScope(p);

        Path wsRoot = workspacesRoot.resolve(p.resourceId()).normalize();
        String rel = relativePath.startsWith("/") ? relativePath.substring(1) : relativePath;
        Path target = wsRoot.resolve(rel).normalize();

        if (!target.startsWith(wsRoot) || !wsRoot.startsWith(workspacesRoot))
            throw new ScopeEnforcer.ScopeViolation("PATH_ESCAPE");

        rejectSymlinks(wsRoot, target);
        return target;
    }

    private void enforceScope(HearthPrincipal p) {
        ScopeEnforcer.of(p.scope()).enforce(p.username(), p.resourceId(), p.namespace());
    }

    private void rejectSymlinks(Path root, Path target) {
        Path current = root;

        for (Path segment : root.relativize(target)) {
            current = current.resolve(segment);
            if (Files.isSymbolicLink(current))
                throw new ScopeEnforcer.ScopeViolation("SYMLINK_REJECTED: " + current);
        }
    }
}