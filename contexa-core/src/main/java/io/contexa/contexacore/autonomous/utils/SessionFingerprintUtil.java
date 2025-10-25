package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.hcad.domain.HCADContext;
import lombok.extern.slf4j.Slf4j;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;

/**
 * 세션 지문 생성 유틸리티
 *
 * SecurityEvent와 HCADContext 모두에서 일관된 세션 지문을 생성합니다.
 * 지문 구성 요소:
 * - 디바이스 지문 (Device Fingerprint): User-Agent 해시
 * - 네트워크 지문 (Network Fingerprint): Source IP 해시
 * - 시간 패턴 지문 (Time Pattern): Hour of day
 * - 행동 패턴 지문 (Behavioral Pattern): Event/Request type
 * - 메타데이터 지문 (Metadata Fingerprint): Additional context 해시
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
public class SessionFingerprintUtil {

    private static final HexFormat HEX_FORMAT = HexFormat.of();

    /**
     * SecurityEvent 로부터 세션 지문 생성
     *
     * @param event 보안 이벤트
     * @return 세션 지문 해시
     */
    public static String generateFingerprint(SecurityEvent event) {
        if (event == null) {
            log.warn("[SessionFingerprint] Event is null, returning default fingerprint");
            return "UNKNOWN";
        }

        StringBuilder fingerprint = new StringBuilder();

        // 1. 디바이스 지문 (Device Fingerprint)
        if (event.getUserAgent() != null) {
            fingerprint.append("UA:").append(hashString(event.getUserAgent())).append("|");
        }

        // 2. 네트워크 지문 (Network Fingerprint)
        if (event.getSourceIp() != null) {
            fingerprint.append("IP:").append(hashString(event.getSourceIp())).append("|");
        }

        // 3. 시간 패턴 지문 (Time Pattern Fingerprint)
        int hourOfDay = event.getTimestamp().getHour();
        fingerprint.append("TH:").append(hourOfDay).append("|");

        // 4. 이벤트 타입 패턴 (Event Pattern Fingerprint)
        fingerprint.append("ET:").append(event.getEventType().toString()).append("|");

        // 5. 메타데이터 지문 (Metadata Fingerprint)
        if (event.getMetadata() != null && !event.getMetadata().isEmpty()) {
            String metadataHash = hashString(event.getMetadata().toString());
            fingerprint.append("MD:").append(metadataHash).append("|");
        }

        // 6. 프로토콜 및 포트 정보
        if (event.getSourcePort() != null) {
            fingerprint.append("SP:").append(event.getSourcePort()).append("|");
        }

        // 최종 지문 해시 생성
        String finalFingerprint = hashString(fingerprint.toString());

        log.debug("[SessionFingerprint] Generated from SecurityEvent - userId: {}, sessionId: {}, fingerprint: {}",
            event.getUserId(), event.getSessionId(), finalFingerprint);

        return finalFingerprint;
    }

    /**
     * HCADContext로부터 세션 지문 생성
     *
     * @param context HCAD 컨텍스트
     * @return 세션 지문 해시
     */
    public static String generateFingerprint(HCADContext context) {
        if (context == null) {
            log.warn("[SessionFingerprint] Context is null, returning default fingerprint");
            return "UNKNOWN";
        }

        StringBuilder fingerprint = new StringBuilder();

        // 1. 디바이스 지문 (Device Fingerprint)
        if (context.getUserAgent() != null) {
            fingerprint.append("UA:").append(hashString(context.getUserAgent())).append("|");
        }

        // 2. 네트워크 지문 (Network Fingerprint)
        if (context.getRemoteIp() != null) {
            fingerprint.append("IP:").append(hashString(context.getRemoteIp())).append("|");
        }

        // 3. 시간 패턴 지문 (Time Pattern Fingerprint)
        if (context.getTimestamp() != null) {
            LocalDateTime dateTime = LocalDateTime.ofInstant(context.getTimestamp(),
                java.time.ZoneId.systemDefault());
            int hourOfDay = dateTime.getHour();
            fingerprint.append("TH:").append(hourOfDay).append("|");
        }

        // 4. 요청 패턴 (Request Pattern Fingerprint)
        if (context.getHttpMethod() != null && context.getRequestPath() != null) {
            fingerprint.append("RT:")
                .append(context.getHttpMethod())
                .append(":")
                .append(hashString(context.getRequestPath()))
                .append("|");
        }

        // 5. 메타데이터 지문 (Metadata Fingerprint)
        if (context.getAdditionalAttributes() != null && !context.getAdditionalAttributes().isEmpty()) {
            String metadataHash = hashString(context.getAdditionalAttributes().toString());
            fingerprint.append("MD:").append(metadataHash).append("|");
        }

        // 최종 지문 해시 생성
        String finalFingerprint = hashString(fingerprint.toString());

        log.debug("[SessionFingerprint] Generated from HCADContext - userId: {}, sessionId: {}, fingerprint: {}",
            context.getUserId(), context.getSessionId(), finalFingerprint);

        return finalFingerprint;
    }

    /**
     * 문자열을 SHA-256 해시로 변환 (앞 8자리만 사용)
     *
     * @param input 입력 문자열
     * @return 해시 값 (8자리)
     */
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

    /**
     * 두 지문 간 유사도 계산 (Levenshtein Distance 기반)
     *
     * @param fp1 지문 1
     * @param fp2 지문 2
     * @return 유사도 (0.0 ~ 1.0)
     */
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

    /**
     * Levenshtein Distance 계산
     *
     * @param s1 문자열 1
     * @param s2 문자열 2
     * @return 편집 거리
     */
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
                        dp[i - 1][j] + 1,      // 삭제
                        dp[i][j - 1] + 1       // 삽입
                    ),
                    dp[i - 1][j - 1] + cost    // 교체
                );
            }
        }

        return dp[len1][len2];
    }
}