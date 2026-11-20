package com.antar.nasorchestrator.controller;

import com.antar.nasorchestrator.dto.CreateWorkspaceRequest;
import com.antar.nasorchestrator.dto.CreateWorkspaceResponse;
import com.antar.nasorchestrator.service.WorkspaceService;
import com.antar.nasorchestrator.util.ScopeWorkspaceByUsername;
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
    private final ScopeWorkspaceByUsername scopeWorkspaceByUsername;

    public WorkspaceController(WorkspaceService workspaceService, ScopeWorkspaceByUsername scopeWorkspaceByUsername) {
        this.workspaceService = workspaceService;
        this.scopeWorkspaceByUsername = scopeWorkspaceByUsername;
    }

    @PostMapping("/create")
    public ResponseEntity<CreateWorkspaceResponse> createWorkspace(@Valid @RequestBody CreateWorkspaceRequest request) throws IOException {
        return ResponseEntity.status(HttpStatus.CREATED).body(workspaceService.createWorkspace(request.name()));
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> deleteWorkspace(HttpServletRequest request) throws IOException {
        workspaceService.deleteWorkspace(scopeWorkspaceByUsername.workspaceRoot(request));
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/clear")
    public ResponseEntity<Void> clearWorkspace(HttpServletRequest request) throws IOException {
        workspaceService.clearWorkspace(scopeWorkspaceByUsername.workspaceRoot(request));
        return ResponseEntity.noContent().build();
    }
}
