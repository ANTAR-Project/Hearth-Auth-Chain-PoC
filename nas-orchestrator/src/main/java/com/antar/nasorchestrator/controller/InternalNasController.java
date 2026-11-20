package com.antar.nasorchestrator.controller;

import com.antar.hearth.common.ScopeEnforcer;
import com.antar.nasorchestrator.dto.FileListResponse;
import com.antar.nasorchestrator.dto.FileUploadResponse;
import com.antar.nasorchestrator.hearth.HearthPrincipal;
import com.antar.nasorchestrator.hearth.WorkspaceAccess;
import com.antar.nasorchestrator.service.FileService;
import com.antar.nasorchestrator.util.MimeTypeResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/internal/nas")
public class InternalNasController {
    private final WorkspaceAccess workspaceAccess;
    private final FileService fileService;
    private final MimeTypeResolver mimeTypeResolver;

    public InternalNasController(
        WorkspaceAccess workspaceAccess,
        FileService fileService,
        MimeTypeResolver mimeTypeResolver) {
        this.workspaceAccess = workspaceAccess;
        this.fileService = fileService;
        this.mimeTypeResolver = mimeTypeResolver;
    }

    /**
     * List directory contents scoped to the caller's principal.
     */
    @GetMapping("/files/list")
    public ResponseEntity<FileListResponse> listFiles(
        @RequestParam(defaultValue = "") String path,
        HttpServletRequest req
    ) throws IOException {
        HearthPrincipal p = principal(req);
        Path resolved = workspaceAccess.resolve(p, path);
        FileListResponse body = fileService.list(resolved.toString(), p.username());

        return ResponseEntity.ok(body);
    }

    /**
     * Stream a file down to the caller. Response is written directly into HttpServletResponse.
     */
    @GetMapping("/files/**")
    public void downloadFile(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HearthPrincipal p = principal(req);
        String subPath = req.getRequestURI().replaceFirst("/internal/nas/files", "");
        Path resolved = workspaceAccess.resolve(p, subPath);
        fileService.download(resolved.toString(), res);
    }

    /**
     * Upload (create or overwrite) a single file via multipart.
     * The resolved path becomes the destination directory; the filename comes from the part.
     */
    @PutMapping("/files/**")
    public ResponseEntity<FileUploadResponse> uploadFile(
        HttpServletRequest req,
        @RequestParam("file") MultipartFile file) throws IOException {
        HearthPrincipal p = principal(req);
        String subPath = req.getRequestURI().replaceFirst("/internal/nas/files", "");
        Path resolved = workspaceAccess.resolve(p, subPath);
        FileUploadResponse body = fileService.upload(resolved.toString(), file);

        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    /**
     * Preview a file inline (images, PDFs, text, etc.).
     * Falls back to 415 if the MIME type is not previewable.
     */
    @GetMapping("/files/preview")
    public ResponseEntity<InputStreamResource> previewFile(
        @RequestParam String path,
        HttpServletRequest req) throws IOException {
        HearthPrincipal p = principal(req);
        Path resolved = workspaceAccess.resolve(p, path);
        String filename = resolved.getFileName().toString();

        if (!mimeTypeResolver.isPreviewable(filename)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).build();
        }

        InputStream stream = fileService.preview(resolved.toString());
        MediaType mediaType = mimeTypeResolver.resolve(filename);

        return ResponseEntity.ok()
            .contentType(mediaType)
            .header(HttpHeaders.CONTENT_DISPOSITION,
                ContentDisposition.inline().filename(filename).build().toString())
            .body(new InputStreamResource(stream));
    }

    /**
     * Initiate a chunked/resumable upload session.
     * Scope + traversal check is performed eagerly; actual data arrives via PUT /files/**.
     */
    @PostMapping("/uploads")
    public ResponseEntity<Map<String, Object>> initUpload(
        @RequestParam String path,
        HttpServletRequest req) {
        HearthPrincipal p = principal(req);
        workspaceAccess.resolve(p, path);

        String uploadId = "u-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        return ResponseEntity.ok(Map.of("uploadId", uploadId, "path", path));
    }

    @ExceptionHandler(ScopeEnforcer.ScopeViolation.class)
    public ResponseEntity<Map<String, Object>> handleScopeViolation(ScopeEnforcer.ScopeViolation e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(Map.of("status", 403, "code", "SCOPE_VIOLATION", "detail", e.getMessage()));
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<Map<String, Object>> handleIo(IOException e) {
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
            .body(Map.of("status", 502, "code", "NAS_IO_ERROR", "detail", e.getMessage()));
    }

    private HearthPrincipal principal(HttpServletRequest req) {
        HearthPrincipal p = (HearthPrincipal) req.getAttribute(HearthPrincipal.ATTR);

        if (p == null)
            throw new IllegalStateException("No HearthPrincipal — ContextTokenFilter not applied");
        return p;
    }
}