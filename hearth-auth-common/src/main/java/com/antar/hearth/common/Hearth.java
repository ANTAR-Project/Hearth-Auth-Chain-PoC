package com.antar.hearth.common;

public final class Hearth {
    public static final String CTX_HEADER = "X-Hearth-Context";
    public static final String INTENT_HEADER = "X-Hearth-Intent-Id";
    public static final String TYP_ACCESS = "at+jwt";
    public static final String TYP_CTX = "hearth-ctx+jwt";
    public static final String TYP_TICKET = "hearth-ticket+jwt";
    public static final String ISS_GATEWAY = "hearth-gateway";
    public static final String ISS_AUTH = "hearth-auth";

    private Hearth() {
    }
}
