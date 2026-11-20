package com.antar.hearth.common;

public record ProblemDetails(
    String type,
    String title,
    int status,
    String code,
    String intentId,
    String traceId
) {
    public static ProblemDetails of(int status, String code) {
        return new ProblemDetails("about:blank",
            code.replace('_', ' ').toLowerCase(), status, code, null, null);
    }

    public ProblemDetails withIntentId(String id) {
        return new ProblemDetails(
            type,
            title,
            status,
            code,
            id,
            traceId
        );
    }

    public ProblemDetails withTraceId(String id) {
        return new ProblemDetails(
            type,
            title,
            status,
            code,
            intentId,
            id
        );
    }
}
