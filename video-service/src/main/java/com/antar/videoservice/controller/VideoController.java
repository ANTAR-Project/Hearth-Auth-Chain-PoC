package com.antar.videoservice.controller;

import com.antar.videoservice.hearth.HearthPrincipal;
import com.antar.videoservice.service.VideoService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/videos")
@Slf4j
@RequiredArgsConstructor
@Validated
public class VideoController {

    private final VideoService videoService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadVideo(
        HttpServletRequest request,
        @RequestParam(value = "path", defaultValue = "") String path,
        @RequestParam("file") MultipartFile file
    ) throws IOException {
        HearthPrincipal p = (HearthPrincipal) request.getAttribute(HearthPrincipal.ATTR);
        if (p == null) return ResponseEntity.status(401).body("AUTH_INVALID");

        log.info("Video upload request from {} of size = {} MB", p.username(), file.getSize() / (1024 * 1024));

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("File is empty");
        }

        String videoKey = videoService.uploadVideo(path, file, p);

        return ResponseEntity.ok("video uploaded successfully! Key = " + videoKey + " : Encoding started automatically via Kafka");
    }
}
