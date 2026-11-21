package com.antar.nasorchestrator.controller;

import com.antar.hearth.common.ScopeEnforcer;
import com.antar.nasorchestrator.dto.CreateFolderResponse;
import com.antar.nasorchestrator.dto.FileListResponse;
import com.antar.nasorchestrator.dto.FileUploadResponse;
import com.antar.nasorchestrator.dto.FolderUploadResponse;
import com.antar.nasorchestrator.hearth.HearthPrincipal;
import com.antar.nasorchestrator.service.SharedWorkspaceService;
import com.antar.nasorchestrator.util.MimeTypeResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.*;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;

@RestController
@RequestMapping("/api/v1/nas-orchestrator/shared")
@Validated
public class SharedWorkspaceController {

    private final SharedWorkspaceService sharedWorkspaceService;
    private final MimeTypeResolver mimeTypeResolver;

    public SharedWorkspaceController(SharedWorkspaceService sharedWorkspaceService, MimeTypeResolver mimeTypeResolver) {
        this.sharedWorkspaceService = sharedWorkspaceService;
        this.mimeTypeResolver = mimeTypeResolver;
    }

    /** Enforces SHARED scope; path is NOT username-prefixed for shared workspace. */
    private HearthPrincipal principal(HttpServletRequest request) {
        HearthPrincipal p = (HearthPrincipal) request.getAttribute(HearthPrincipal.ATTR);
        if (p == null) throw new IllegalStateException("Missing HearthPrincipal — ContextTokenFilter did not run");
        ScopeEnforcer.of(p.scope()).enforce(p.username(), p.resourceId(), p.namespace());
        return p;
    }

    @GetMapping("/list")
    public ResponseEntity<FileListResponse> list(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path
    ) throws IOException {
        principal(request);  // enforce SHARED scope
        return ResponseEntity.ok(sharedWorkspaceService.listSharedWorkspace(path));
    }

    @PostMapping("/upload/file")
    public ResponseEntity<FileUploadResponse> uploadFile(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path,
        @RequestParam("file") MultipartFile file
    ) throws IOException {
        principal(request);
        return ResponseEntity.ok(sharedWorkspaceService.uploadToSharedWorkspace(path, file));
    }

    @PostMapping("/upload/folder")
    public ResponseEntity<FolderUploadResponse> uploadFolder(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path,
        @RequestParam("files") MultipartFile[] files,
        @RequestParam("relativePaths") String[] relativePaths
    ) throws IOException {
        principal(request);
        return ResponseEntity.ok(sharedWorkspaceService.uploadFolderToSharedWorkspace(path, files, relativePaths));
    }

    @GetMapping("/download")
    public void download(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path,
        HttpServletResponse response
    ) throws IOException {
        principal(request);
        sharedWorkspaceService.downloadFromSharedWorkspace(path, response);
    }

    @GetMapping("/preview")
    public ResponseEntity<InputStreamResource> preview(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path
    ) throws IOException {
        principal(request);
        String filename = path.substring(path.lastIndexOf('/') + 1);

        if (!mimeTypeResolver.isPreviewable(filename)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).build();
        }

        InputStream inputStream = sharedWorkspaceService.previewFileInSharedWorkspace(path);
        MediaType mediaType = mimeTypeResolver.resolve(filename);

        return ResponseEntity.ok()
            .contentType(mediaType)
            .header(HttpHeaders.CONTENT_DISPOSITION,
                ContentDisposition.inline().filename(filename).build().toString())
            .body(new InputStreamResource(inputStream));
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> delete(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path
    ) throws IOException {
        principal(request);
        sharedWorkspaceService.deleteFromSharedWorkspace(path);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/mkdir")
    public ResponseEntity<CreateFolderResponse> mkdir(
        HttpServletRequest request,
        @RequestParam("path") String path
    ) throws IOException {
        principal(request);
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(sharedWorkspaceService.createFolderInSharedWorkspace(path));
    }

    @DeleteMapping("/clear")
    public ResponseEntity<Void> clear(HttpServletRequest request) throws IOException {
        principal(request);
        sharedWorkspaceService.clearSharedWorkspace();
        return ResponseEntity.noContent().build();
    }
}

