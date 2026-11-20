package com.antar.nasorchestrator.dto;

public record ValidationOutcome(
    boolean valid,
    boolean reachable,
    String username
) {
}
