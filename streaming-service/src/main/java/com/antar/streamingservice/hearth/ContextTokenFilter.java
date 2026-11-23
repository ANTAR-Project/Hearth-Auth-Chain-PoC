package com.antar.streamingservice.hearth;

import com.antar.hearth.common.BindCalculator;
import com.antar.hearth.common.Hearth;
import com.antar.hearth.common.JwtVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Component
public class ContextTokenFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(ContextTokenFilter.class);
    private final JwtVerifier contextVerifier;

    public ContextTokenFilter(JwtVerifier contextTokenVerifier) {
        this.contextVerifier = contextTokenVerifier;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest req) {
        String uri = req.getRequestURI();
        return uri.startsWith("/actuator") || uri.startsWith("/.well-known");
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest req,
        HttpServletResponse res,
        FilterChain chain
    ) throws ServletException, IOException {
        String ctx = req.getHeader(Hearth.CTX_HEADER);
        if (ctx == null) {
            write(res, 401, "AUTH_INVALID");
            return;
        }

        try {
            JWTClaimsSet claims = contextVerifier.verify(ctx);

            String expectedBind = BindCalculator.bind(
                req.getMethod(),
                req.getRequestURI(),
                req.getQueryString(),
                req.getHeader("X-Checksum-SHA256"),
                null
            );

            String tokenBind = claims.getStringClaim("bind");
            if (tokenBind == null || !MessageDigest.isEqual(
                expectedBind.getBytes(StandardCharsets.UTF_8),
                tokenBind.getBytes(StandardCharsets.UTF_8))) {
                write(res, 403, "INTENT_BINDING_MISMATCH");
                return;
            }

            req.setAttribute(HearthPrincipal.ATTR, HearthPrincipal.fromContextToken(claims));
            log.info("[CONTEXT_TOKEN_ACCEPTED] Service [streaming-service] verified token: user={} role={} intent={} action={}",
                claims.getStringClaim("username"),
                claims.getStringClaim("role"),
                claims.getStringClaim("name"),
                claims.getStringClaim("action"));
            chain.doFilter(req, res);
        } catch (JwtVerifier.Rejected e) {
            write(res, 401, "AUTH_INVALID");
        } catch (JwtVerifier.Unavailable e) {
            write(res, 503, "AUTH_UNAVAILABLE");
        } catch (Exception e) {
            write(res, 401, "AUTH_INVALID");
        }
    }

    private void write(HttpServletResponse r, int status, String code) throws IOException {
        r.setStatus(status);
        r.setContentType("application/problem+json");
        r.getWriter().write("{\"status\":" + status + ",\"code\":\"" + code + "\"}");
    }
}
