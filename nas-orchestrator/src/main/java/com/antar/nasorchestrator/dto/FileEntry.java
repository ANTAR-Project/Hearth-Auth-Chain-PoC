package com.antar.nasorchestrator.dto;

public record FileEntry(
    String name,
    long size,
    boolean isDirectory,
    long lastModified
) {
}
