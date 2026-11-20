package com.antar.notificationservice.dto;

public record ValidationOutcome(
    boolean valid,
    boolean reachable,
    String username
) {
}
