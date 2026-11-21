package com.antar.apigateway.gateway;

import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.web.server.ServerWebExchange;

import java.util.Map;

public record RouteMeta(
    String intent, String action, String domain, String clazz,
    String audience, String resourceType, String resourceId,
    String qualifier, String namespace, String upstreamPath,
    boolean publicRoute, boolean skipPolicy,
    Map<String, String> params
) {
    @SuppressWarnings("unchecked")
    public static RouteMeta of(ServerWebExchange ex) {
        Route route = ex.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        if (route == null) return null;

        Object raw = route.getMetadata().get("hearth");
        if (!(raw instanceof Map<?, ?> m)) return null;
        
        Map<String, Object> h = (Map<String, Object>) m;
        return new RouteMeta(
            s(h, "intent"), s(h, "action"), s(h, "domain"), s(h, "class"),
            s(h, "audience"), s(h, "resourceType"), s(h, "resourceId"),
            s(h, "qualifier"), s(h, "namespace"), s(h, "upstreamPath"),
            Boolean.parseBoolean(s(h, "public")),
            Boolean.parseBoolean(s(h, "bypass-policy")) || Boolean.parseBoolean(s(h, "skipPolicy")),
            h.containsKey("params") ? (Map<String, String>) h.get("params") : Map.of());
    }

    private static String s(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? null : v.toString();
    }
}