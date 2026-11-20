package com.antar.nasorchestrator.dto;

import java.util.List;

public record FileListResponse(String path, List<FileEntry> entry) {
}
