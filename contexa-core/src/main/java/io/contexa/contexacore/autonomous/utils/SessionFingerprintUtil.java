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
            log.warn("[SessionFingerprint] Event is null, returning default fingerprint");
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

        String finalFingerprint = hashString(fingerprint.toString());

        return finalFingerprint;
    }

    public static String generateFingerprint(HCADContext context) {
        if (context == null) {
            log.warn("[SessionFingerprint] Context is null, returning default fingerprint");
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

        String finalFingerprint = hashString(fingerprint.toString());

        return finalFingerprint;
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

    public static String generateContextBindingHash(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        return generateContextBindingHash(
                request.getRequestedSessionId(),
                extractClientIp(request),
                request.getHeader("User-Agent")
        );
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

    private static String extractClientIp(HttpServletRequest request) {
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

    public static double calculateSimilarity(String fp1, String fp2) {
        if (fp1 == null || fp2 == null) {
            return 0.0;
        }

        if (fp1.equals(fp2)) {
            return 1.0;
        }

        int distance = levenshteinDistance(fp1, fp2);
        int maxLength = Math.max(fp1.length(), fp2.length());

        if (maxLength == 0) {
            return 1.0;
        }

        return 1.0 - ((double) distance / maxLength);
    }

    private static int levenshteinDistance(String s1, String s2) {
        int len1 = s1.length();
        int len2 = s2.length();

        int[][] dp = new int[len1 + 1][len2 + 1];

        for (int i = 0; i <= len1; i++) {
            dp[i][0] = i;
        }

        for (int j = 0; j <= len2; j++) {
            dp[0][j] = j;
        }

        for (int i = 1; i <= len1; i++) {
            for (int j = 1; j <= len2; j++) {
                int cost = (s1.charAt(i - 1) == s2.charAt(j - 1)) ? 0 : 1;

                dp[i][j] = Math.min(
                    Math.min(
                        dp[i - 1][j] + 1,      
                        dp[i][j - 1] + 1       
                    ),
                    dp[i - 1][j - 1] + cost    
                );
            }
        }

        return dp[len1][len2];
    }
}