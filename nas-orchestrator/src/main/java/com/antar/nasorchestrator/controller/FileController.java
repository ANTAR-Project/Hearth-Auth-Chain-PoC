package com.antar.nasorchestrator.controller;

import com.antar.hearth.common.ScopeEnforcer;
import com.antar.nasorchestrator.dto.CreateFolderResponse;
import com.antar.nasorchestrator.dto.FileListResponse;
import com.antar.nasorchestrator.dto.FileUploadResponse;
import com.antar.nasorchestrator.dto.FolderUploadResponse;
import com.antar.nasorchestrator.hearth.HearthPrincipal;
import com.antar.nasorchestrator.service.FileService;
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
@RequestMapping("/api/v1/nas-orchestrator/files")
@Validated
public class FileController {

    private final FileService fileService;
    private final MimeTypeResolver mimeTypeResolver;

    public FileController(FileService fileService, MimeTypeResolver mimeTypeResolver) {
        this.fileService = fileService;
        this.mimeTypeResolver = mimeTypeResolver;
    }

    /** Extracts and enforces the HearthPrincipal placed by ContextTokenFilter. */
    private HearthPrincipal principal(HttpServletRequest request) {
        HearthPrincipal p = (HearthPrincipal) request.getAttribute(HearthPrincipal.ATTR);
        if (p == null) throw new IllegalStateException("Missing HearthPrincipal — ContextTokenFilter did not run");
        ScopeEnforcer.of(p.scope()).enforce(p.username(), p.resourceId(), p.namespace());
        return p;
    }

    /** Builds the SMB-relative path: resourceId (e.g. "alice") / relative-path */
    private static String scopedPath(HearthPrincipal p, String path) {
        return path.isEmpty() ? p.resourceId() : p.resourceId() + "/" + path;
    }

    @PostMapping("/upload/file")
    public ResponseEntity<FileUploadResponse> uploadFile(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path,
        @RequestParam("file") MultipartFile file
    ) throws IOException {
        HearthPrincipal p = principal(request);
        return ResponseEntity.ok(fileService.upload(scopedPath(p, path), file));
    }

    @PostMapping("/upload/folder")
    public ResponseEntity<FolderUploadResponse> uploadFolder(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path,
        @RequestParam("files") MultipartFile[] files,
        @RequestParam("relativePaths") String[] relativePaths
    ) throws IOException {
        HearthPrincipal p = principal(request);
        return ResponseEntity.ok(fileService.uploadFolder(scopedPath(p, path), files, relativePaths));
    }

    @GetMapping("/download")
    public void download(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path,
        HttpServletResponse response
    ) throws IOException {
        HearthPrincipal p = principal(request);
        fileService.download(scopedPath(p, path), response);
    }

    @GetMapping("/preview")
    public ResponseEntity<InputStreamResource> preview(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path
    ) throws IOException {
        HearthPrincipal p = principal(request);
        String scoped = scopedPath(p, path);
        String filename = scoped.substring(scoped.lastIndexOf('/') + 1);

        if (!mimeTypeResolver.isPreviewable(filename)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).build();
        }

        InputStream inputStream = fileService.preview(scoped);
        MediaType mediaType = mimeTypeResolver.resolve(filename);

        return ResponseEntity.ok()
            .contentType(mediaType)
            .header(HttpHeaders.CONTENT_DISPOSITION,
                ContentDisposition.inline().filename(filename).build().toString())
            .body(new InputStreamResource(inputStream));
    }

    @GetMapping("/list")
    public ResponseEntity<FileListResponse> list(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path
    ) throws IOException {
        HearthPrincipal p = principal(request);
        return ResponseEntity.ok(fileService.list(scopedPath(p, path), p.username()));
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> delete(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path
    ) throws IOException {
        HearthPrincipal p = principal(request);
        fileService.delete(scopedPath(p, path), p.username());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/mkdir")
    public ResponseEntity<CreateFolderResponse> mkdir(
        HttpServletRequest request,
        @RequestParam("path") String path
    ) throws IOException {
        HearthPrincipal p = principal(request);
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(fileService.createFolder(scopedPath(p, path), p.username()));
    }
}
