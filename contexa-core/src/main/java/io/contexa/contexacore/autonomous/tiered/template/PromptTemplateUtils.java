package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.Map;

/**
 * PromptTemplate 공통 유틸리티 클래스
 *
 * Layer1/Layer2/Layer3 PromptTemplate에서 중복되는 메서드들을 통합합니다.
 * - 데이터 유효성 검사
 * - metadata 추출
 * - 데이터 품질 계산
 * - 문자열 처리
 *
 * @author contexa
 * @since 1.0
 */
public final class PromptTemplateUtils {

    private PromptTemplateUtils() {
        // 유틸리티 클래스 - 인스턴스 생성 방지
    }

    /**
     * 데이터가 유효한지 검사 (null, empty, "unknown" 제외)
     *
     * @param value 검사할 문자열
     * @return 유효하면 true
     */
    public static boolean isValidData(String value) {
        return value != null && !value.isEmpty() && !value.equalsIgnoreCase("unknown");
    }

    /**
     * metadata에서 문자열 값 안전하게 추출 (AI Native)
     *
     * AI Native 원칙: 기본값 "unknown" 제거
     * - 값이 없으면 null 반환
     * - 호출부에서 null 체크 후 프롬프트 생략
     * - LLM이 "unknown" 문자열을 실제 데이터로 오인하는 문제 방지
     *
     * @param metadata 메타데이터 맵
     * @param key 추출할 키
     * @return 문자열 값 또는 null
     */
    public static String getStringFromMetadata(Map<String, Object> metadata, String key) {
        if (metadata == null) {
            return null;
        }
        Object value = metadata.get(key);
        if (value == null) {
            return null;
        }
        String strValue = value.toString();
        return strValue.isEmpty() ? null : strValue;
    }

    /**
     * 클래스 풀네임에서 심플 클래스명 추출 (AI Native)
     * 예: "io.contexa.service.TestService" -> "TestService"
     *
     * AI Native 원칙: 기본값 "unknown" 제거
     * - 값이 없으면 null 반환
     *
     * @param fullClassName 전체 클래스명
     * @return 심플 클래스명 또는 null
     */
    public static String extractSimpleClassName(String fullClassName) {
        if (fullClassName == null || fullClassName.isEmpty()) {
            return null;
        }
        int lastDot = fullClassName.lastIndexOf('.');
        if (lastDot >= 0 && lastDot < fullClassName.length() - 1) {
            return fullClassName.substring(lastDot + 1);
        }
        return fullClassName;
    }

    /**
     * 데이터 품질 점수 계산 (0-10)
     * LLM이 판단의 신뢰도를 조절하는 데 참고
     *
     * @param event 보안 이벤트
     * @return 데이터 품질 점수 (0-10)
     */
    public static int calculateDataQuality(SecurityEvent event) {
        int score = 0;

        // 필수 정보
        if (event.getEventType() != null) score++;
        if (event.getSeverity() != null) score++;
        if (isValidData(event.getUserId())) score++;
        if (isValidData(event.getSourceIp())) score++;
        if (isValidData(event.getUserAgent())) score++;

        // 추가 정보
        if (isValidData(event.getSessionId())) score++;
        if (isValidData(event.getTargetResource())) score++;
        if (event.getTimestamp() != null) score++;

        // metadata 정보
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && !metadata.isEmpty()) {
            if (metadata.containsKey("authz.resource")) score++;
            if (metadata.containsKey("methodClass")) score++;
        }

        return Math.min(10, score);
    }

    /**
     * Zero Trust: 데이터 품질 및 누락 필드 분석 (AI Native v3.1.0)
     *
     * LLM에게 다음 정보 제공:
     * - 데이터 품질 점수 (0-10)
     * - 누락된 필드 목록 (Missing: sourceIp, sessionId)
     * - 필수 필드 누락 시 CRITICAL 경고
     *
     * Zero Trust 원칙: "Never Trust, Always Verify"
     * - 필수 필드(IP, SessionId)가 없으면 검증 불가
     * - LLM이 ALLOW를 반환하지 않도록 경고 제공
     *
     * @param event 보안 이벤트
     * @return 데이터 품질 분석 문자열
     */
    public static String buildDataQualitySection(SecurityEvent event) {
        StringBuilder result = new StringBuilder();
        java.util.List<String> missingFields = new java.util.ArrayList<>();
        java.util.List<String> missingCriticalFields = new java.util.ArrayList<>();
        int score = 0;

        // 필수 정보 (Critical)
        if (event.getEventType() != null) {
            score++;
        } else {
            missingFields.add("eventType");
        }

        if (event.getSeverity() != null) {
            score++;
        } else {
            missingFields.add("severity");
        }

        if (isValidData(event.getUserId())) {
            score++;
        } else {
            missingFields.add("userId");
            missingCriticalFields.add("userId");
        }

        // Zero Trust Critical: IP, SessionId
        if (isValidData(event.getSourceIp())) {
            score++;
        } else {
            missingFields.add("sourceIp");
            missingCriticalFields.add("sourceIp");
        }

        if (isValidData(event.getSessionId())) {
            score++;
        } else {
            missingFields.add("sessionId");
            missingCriticalFields.add("sessionId");
        }

        if (isValidData(event.getUserAgent())) {
            score++;
        } else {
            missingFields.add("userAgent");
        }

        // 추가 정보
        if (isValidData(event.getTargetResource())) {
            score++;
        } else {
            missingFields.add("targetResource");
        }

        if (event.getTimestamp() != null) {
            score++;
        } else {
            missingFields.add("timestamp");
        }

        // metadata 정보
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && !metadata.isEmpty()) {
            if (metadata.containsKey("authz.resource")) {
                score++;
            } else {
                missingFields.add("authz.resource");
            }
            if (metadata.containsKey("methodClass")) {
                score++;
            } else {
                missingFields.add("methodClass");
            }
        } else {
            missingFields.add("authz.resource");
            missingFields.add("methodClass");
        }

        score = Math.min(10, score);

        // 결과 문자열 생성
        result.append(String.format("Data Quality: %d/10 fields available\n", score));

        if (!missingFields.isEmpty()) {
            result.append(String.format("Missing: %s\n", String.join(", ", missingFields)));
        }

        // Zero Trust: 필수 필드 누락 시 CRITICAL 경고
        if (!missingCriticalFields.isEmpty()) {
            result.append("\n=== CRITICAL: MISSING VERIFICATION DATA ===\n");
            result.append(String.format("Missing critical fields: %s\n", String.join(", ", missingCriticalFields)));
            result.append("Zero Trust: Cannot verify identity without these fields.\n");
            result.append("RECOMMENDATION: Consider CHALLENGE or ESCALATE action.\n");
        }

        return result.toString();
    }

    /**
     * Authorization 정보 섹션 구성 (AI Native)
     *
     * metadata에서 authz.resource, authz.action, authz.result, authz.reason,
     * methodClass, methodName 등 풍부한 컨텍스트 정보 추출
     *
     * @param event 보안 이벤트
     * @return Authorization 섹션 문자열 (빈 경우 빈 문자열)
     */
    public static String buildAuthzSection(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return "";
        }

        StringBuilder authz = new StringBuilder();

        // authz.resource - 접근 대상 리소스
        String authzResource = getStringFromMetadata(metadata, "authz.resource");
        if (isValidData(authzResource)) {
            authz.append("Resource: ").append(authzResource).append("\n");
        }

        // methodClass, methodName - 호출된 메서드 정보
        String methodClass = getStringFromMetadata(metadata, "methodClass");
        String methodName = getStringFromMetadata(metadata, "methodName");
        if (isValidData(methodClass) || isValidData(methodName)) {
            String classSimpleName = extractSimpleClassName(methodClass);
            if (classSimpleName != null && isValidData(methodName)) {
                authz.append("Method: ").append(classSimpleName).append(".").append(methodName).append("\n");
            } else if (classSimpleName != null) {
                authz.append("Class: ").append(classSimpleName).append("\n");
            } else if (isValidData(methodName)) {
                authz.append("Method: ").append(methodName).append("\n");
            }
        }

        // authz.action - 수행 액션
        String authzAction = getStringFromMetadata(metadata, "authz.action");
        if (isValidData(authzAction)) {
            authz.append("Action: ").append(authzAction).append("\n");
        }

        // authz.result - 인가 결과
        String authzResult = getStringFromMetadata(metadata, "authz.result");
        if (isValidData(authzResult)) {
            authz.append("Result: ").append(authzResult).append("\n");
        }

        // authz.reason - 거부 이유 (있는 경우)
        String authzReason = getStringFromMetadata(metadata, "authz.reason");
        if (isValidData(authzReason)) {
            // 이유가 너무 길면 요약
            if (authzReason.length() > 80) {
                authzReason = authzReason.substring(0, 77) + "...";
            }
            authz.append("Reason: ").append(authzReason).append("\n");
        }

        return authz.toString().trim();
    }

    /**
     * 네트워크 정보 섹션 구성 (유효한 데이터만)
     *
     * @param event 보안 이벤트
     * @return 네트워크 섹션 문자열
     */
    public static String buildNetworkSection(SecurityEvent event) {
        StringBuilder network = new StringBuilder();

        if (isValidData(event.getSourceIp())) {
            network.append("IP: ").append(event.getSourceIp()).append("\n");
        }

        if (isValidData(event.getUserAgent())) {
            String ua = event.getUserAgent();
            if (ua.length() > 150) {
                ua = ua.substring(0, 147) + "...";
            }
            network.append("UserAgent: ").append(ua).append("\n");
        }

        return network.toString().trim();
    }

    /**
     * 문자열을 지정된 길이로 자르기 (truncate)
     *
     * @param value 원본 문자열
     * @param maxLength 최대 길이
     * @return 잘린 문자열 (null이면 null 반환)
     */
    public static String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength - 3) + "...";
    }

    /**
     * 문자열을 지정된 길이로 자르고 null이면 "N/A" 반환
     *
     * @param value 원본 문자열
     * @param maxLength 최대 길이
     * @return 잘린 문자열 또는 "N/A"
     */
    public static String truncateOrNA(String value, int maxLength) {
        if (value == null || value.isEmpty()) {
            return "N/A";
        }
        return truncate(value, maxLength);
    }
}
