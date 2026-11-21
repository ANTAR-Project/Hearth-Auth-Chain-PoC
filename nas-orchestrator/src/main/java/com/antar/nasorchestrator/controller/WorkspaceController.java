package com.antar.nasorchestrator.controller;

import com.antar.hearth.common.ScopeEnforcer;
import com.antar.nasorchestrator.dto.CreateWorkspaceRequest;
import com.antar.nasorchestrator.dto.CreateWorkspaceResponse;
import com.antar.nasorchestrator.hearth.HearthPrincipal;
import com.antar.nasorchestrator.service.WorkspaceService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/nas-orchestrator/workspace")
@Validated
public class WorkspaceController {

    private final WorkspaceService workspaceService;

    public WorkspaceController(WorkspaceService workspaceService) {
        this.workspaceService = workspaceService;
    }

    private HearthPrincipal principal(HttpServletRequest request) {
        HearthPrincipal p = (HearthPrincipal) request.getAttribute(HearthPrincipal.ATTR);
        if (p == null) throw new IllegalStateException("Missing HearthPrincipal — ContextTokenFilter did not run");
        ScopeEnforcer.of(p.scope()).enforce(p.username(), p.resourceId(), p.namespace());
        return p;
    }

    @PostMapping("/create")
    public ResponseEntity<CreateWorkspaceResponse> createWorkspace(
        HttpServletRequest request,
        @Valid @RequestBody CreateWorkspaceRequest body
    ) throws IOException {
        principal(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(workspaceService.createWorkspace(body.name()));
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> deleteWorkspace(HttpServletRequest request) throws IOException {
        HearthPrincipal p = principal(request);
        workspaceService.deleteWorkspace(p.resourceId());
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/clear")
    public ResponseEntity<Void> clearWorkspace(HttpServletRequest request) throws IOException {
        HearthPrincipal p = principal(request);
        workspaceService.clearWorkspace(p.resourceId());
        return ResponseEntity.noContent().build();
    }
}

