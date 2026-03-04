package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;

@Slf4j
public class SessionFingerprintUtil {

    private static final HexFormat HEX_FORMAT = HexFormat.of();

    public static String generateFingerprint(SecurityEvent event) {
        if (event == null) {
            log.error("[SessionFingerprint] Event is null, returning default fingerprint");
            return "UNKNOWN";
        }

        StringBuilder fingerprint = new StringBuilder();

        if (event.getUserAgent() != null) {
            fingerprint.append("UA:").append(hashString(event.getUserAgent())).append("|");
        }

        if (event.getSourceIp() != null) {
            fingerprint.append("IP:").append(hashString(event.getSourceIp())).append("|");
        }

        int hourOfDay = event.getTimestamp().getHour();
        fingerprint.append("TH:").append(hourOfDay).append("|");

        fingerprint.append("SV:").append(event.getSeverity() != null ? event.getSeverity().toString() : "INFO").append("|");

        if (event.getMetadata() != null && !event.getMetadata().isEmpty()) {
            String metadataHash = hashString(event.getMetadata().toString());
            fingerprint.append("MD:").append(metadataHash).append("|");
        }

        return hashString(fingerprint.toString());
    }

    public static String generateFingerprint(HCADContext context) {
        if (context == null) {
            log.error("[SessionFingerprint] Context is null, returning default fingerprint");
            return "UNKNOWN";
        }

        StringBuilder fingerprint = new StringBuilder();

        if (context.getUserAgent() != null) {
            fingerprint.append("UA:").append(hashString(context.getUserAgent())).append("|");
        }

        if (context.getRemoteIp() != null) {
            fingerprint.append("IP:").append(hashString(context.getRemoteIp())).append("|");
        }

        if (context.getTimestamp() != null) {
            LocalDateTime dateTime = LocalDateTime.ofInstant(context.getTimestamp(),
                java.time.ZoneId.systemDefault());
            int hourOfDay = dateTime.getHour();
            fingerprint.append("TH:").append(hourOfDay).append("|");
        }

        if (context.getHttpMethod() != null && context.getRequestPath() != null) {
            fingerprint.append("RT:")
                .append(context.getHttpMethod())
                .append(":")
                .append(hashString(context.getRequestPath()))
                .append("|");
        }

        if (context.getAdditionalAttributes() != null && !context.getAdditionalAttributes().isEmpty()) {
            String metadataHash = hashString(context.getAdditionalAttributes().toString());
            fingerprint.append("MD:").append(metadataHash).append("|");
        }

        return hashString(fingerprint.toString());
    }

    private static String hashString(String input) {
        if (input == null || input.isEmpty()) {
            return "00000000";
        }

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String fullHash = HEX_FORMAT.formatHex(hash);
            return fullHash.substring(0, 8);
        } catch (NoSuchAlgorithmException e) {
            log.error("[SessionFingerprint] SHA-256 algorithm not available", e);
            return input.hashCode() + "";
        }
    }

    private static final String CONTEXT_BINDING_HASH_ATTR = "contexa.contextBindingHash";

    public static String generateContextBindingHash(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String cached = (String) request.getAttribute(CONTEXT_BINDING_HASH_ATTR);
        if (cached != null) {
            return cached;
        }
        String hash = generateContextBindingHash(
                request.getRequestedSessionId(),
                extractClientIp(request),
                request.getHeader("User-Agent")
        );
        if (hash != null) {
            request.setAttribute(CONTEXT_BINDING_HASH_ATTR, hash);
        }
        return hash;
    }

    public static String generateContextBindingHash(String sessionId, String ip, String userAgent) {
        if (sessionId == null && ip == null && userAgent == null) {
            return null;
        }
        String raw = "CTX:" + (sessionId != null ? sessionId : "")
                + "|" + (ip != null ? ip : "")
                + "|" + (userAgent != null ? userAgent : "");
        return hashStringLong(raw);
    }

    private static String hashStringLong(String input) {
        if (input == null || input.isEmpty()) {
            return "0000000000000000";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HEX_FORMAT.formatHex(hash).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            log.error("[SessionFingerprint] SHA-256 algorithm not available", e);
            return String.valueOf(input.hashCode());
        }
    }

    public static String extractClientIp(HttpServletRequest request) {
        String[] headers = {
                "X-Forwarded-For", "X-Real-IP", "Proxy-Client-IP",
                "WL-Proxy-Client-IP", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR"
        };
        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                if (ip.contains(",")) {
                    return ip.split(",")[0].trim();
                }
                return ip.trim();
            }
        }
        return request.getRemoteAddr();
    }
}
