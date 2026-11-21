package com.antar.videoservice.service;

import com.antar.videoservice.client.NasOrchestratorClient;
import com.antar.videoservice.event.VideoUploadedEvent;
import com.antar.videoservice.hearth.HearthPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Service
@Slf4j
@RequiredArgsConstructor
public class VideoService {
    private final KafkaTemplate<String, VideoUploadedEvent> kafkaTemplate;
    private final NasOrchestratorClient nasOrchestratorClient;

    private static final String VIDEO_UPLOADED_TOPIC = "video.uploaded";

    public String uploadVideo(String path, MultipartFile file, HearthPrincipal p) throws IOException {
        // resourceId == username workspace root (enforced by ScopeEnforcer on the gateway side)
        String workspaceRoot = p.resourceId();
        String scopedPath = path.isEmpty() ? workspaceRoot : workspaceRoot + "/" + path;

        log.info("Uploading video {} to NAS : file - {}", scopedPath, file.getOriginalFilename());

        String nasPath = nasOrchestratorClient.uploadFile(scopedPath, file);
        log.info("Video uploaded to NAS successfully: path = {}", nasPath);

        VideoUploadedEvent videoUploadedEvent = new VideoUploadedEvent(
            workspaceRoot,
            path,
            nasPath,
            file.getOriginalFilename(),
            file.getSize()
        );

        kafkaTemplate.send(VIDEO_UPLOADED_TOPIC, nasPath, videoUploadedEvent);
        log.info("Video uploaded event published to Kafka: key = {}", nasPath);

        return nasPath;
    }
}
