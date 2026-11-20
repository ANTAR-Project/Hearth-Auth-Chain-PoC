package com.antar.videoservice.dto;

public record ValidationOutcome(
    boolean valid,
    boolean reachable,
    String username
) {
}
