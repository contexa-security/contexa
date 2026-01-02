package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.Map;
import java.util.regex.Pattern;

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
        if (event.getSeverity() != null) score++;
        if (isValidData(event.getUserId())) score++;
        if (isValidData(event.getSourceIp())) score++;
        if (isValidData(event.getUserAgent())) score++;

        // 추가 정보
        if (isValidData(event.getSessionId())) score++;
        if (event.getTimestamp() != null) score++;

        // metadata 정보
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && !metadata.isEmpty()) {
            if (metadata.containsKey("methodClass")) score++;
        }

        return Math.min(10, score);
    }

    /**
     * Zero Trust v6.0: 데이터 품질 및 누락 필드 분석 (전면 재설계)
     *
     * 이전 문제점 (v3.1.0):
     * - 7개 기본 필드만 평가, baseline/trustScore 미포함
     * - "7/10" 표시가 LLM에게 "70% 충분" 오해 유발
     * - 가장 중요한 필드(baseline)가 평가에서 누락
     *
     * Zero Trust v6.0 개선:
     * - CRITICAL 필드: baseline, userId, sourceIp, sessionId (4개)
     * - HIGH 필드: isNewSession, isNewDevice, recentRequestCount (3개)
     * - 7개 필드 기준으로 정확한 점수 계산
     * - baseline 없으면 강제 경고 추가
     *
     * AI Native v4.3.0: trustScore를 CRITICAL 필드에서 제거
     * - LLM은 riskScore만 반환하며 trustScore(=1-riskScore)는 역관계로 혼란 유발
     * - trustScore는 내부 EMA 학습용으로만 사용
     *
     * @param event 보안 이벤트
     * @param baselineContext baseline 컨텍스트 (null이면 baseline 없음으로 판단)
     * @return 데이터 품질 분석 문자열
     */
    public static String buildDataQualitySection(SecurityEvent event, String baselineContext) {
        StringBuilder result = new StringBuilder();
        java.util.List<String> criticalMissing = new java.util.ArrayList<>();
        java.util.List<String> criticalPresent = new java.util.ArrayList<>();
        java.util.List<String> highMissing = new java.util.ArrayList<>();

        // 1. CRITICAL 필드 평가 (의사결정 필수)

        // baseline 존재 여부 (가장 중요!)
        boolean hasBaseline = baselineContext != null
            && !baselineContext.startsWith("[NO")
            && !baselineContext.startsWith("[SERVICE")
            && !baselineContext.contains("CRITICAL: NO USER BASELINE")
            && !baselineContext.contains("[NEW_USER]");
        if (hasBaseline) {
            criticalPresent.add("baseline");
        } else {
            criticalMissing.add("baseline");
        }

        // AI Native v4.3.0: trustScore 체크 제거
        // LLM은 riskScore만 반환하며, trustScore는 내부 EMA 학습용으로만 사용

        // userId
        if (isValidData(event.getUserId())) {
            criticalPresent.add("userId");
        } else {
            criticalMissing.add("userId");
        }

        // sourceIp
        if (isValidData(event.getSourceIp())) {
            criticalPresent.add("sourceIp");
        } else {
            criticalMissing.add("sourceIp");
        }

        // sessionId
        if (isValidData(event.getSessionId())) {
            criticalPresent.add("sessionId");
        } else {
            criticalMissing.add("sessionId");
        }

        // 2. HIGH 필드 평가 (중요하지만 필수 아님)
        if (metadata == null || !metadata.containsKey("isNewSession")) {
            highMissing.add("isNewSession");
        }
        if (metadata == null || !metadata.containsKey("isNewDevice")) {
            highMissing.add("isNewDevice");
        }
        if (metadata == null || !metadata.containsKey("recentRequestCount")) {
            highMissing.add("recentRequestCount");
        }

        // 3. 점수 계산 (CRITICAL 5개 + HIGH 3개 = 8개 기준)
        int score = criticalPresent.size() + (3 - highMissing.size());
        int maxScore = 8;

        // 4. 결과 출력
        result.append(String.format("Decision Data: %d/%d fields available\n", score, maxScore));

        if (!criticalMissing.isEmpty()) {
            result.append(String.format("CRITICAL MISSING: %s\n", String.join(", ", criticalMissing)));
        }
        if (!highMissing.isEmpty()) {
            result.append(String.format("HIGH MISSING: %s\n", String.join(", ", highMissing)));
        }

        // 5. baseline 없으면 강제 경고 (Zero Trust v6.0 핵심)
        if (!hasBaseline) {
            result.append("\n=== WARNING: NO BASELINE DATA ===\n");
            result.append("- Cannot verify if behavior is normal\n");
            result.append("- ALLOW decision is NOT recommended\n");
            result.append("- Suggested action: CHALLENGE or ESCALATE\n");
        }

        return result.toString();
    }

    /**
     * 하위 호환성 유지를 위한 기존 메서드 (deprecated)
     *
     * @param event 보안 이벤트
     * @return 데이터 품질 분석 문자열
     * @deprecated Zero Trust v6.0: baseline 파라미터를 포함하는 오버로드 메서드 사용 권장
     */
    @Deprecated
    public static String buildDataQualitySection(SecurityEvent event) {
        // baseline 정보 없이 호출되면 baseline 없음으로 판단
        return buildDataQualitySection(event, null);
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

    /**
     * 사용자 입력 새니타이징 - 프롬프트 인젝션 방어 (AI Native v3.3.0)
     *
     * LLM 프롬프트에 포함되는 사용자 입력값에서 특수 문자를 이스케이프하여
     * 프롬프트 인젝션 공격을 방지합니다.
     *
     * 방어 대상:
     * - 백슬래시(\): 이스케이프 시퀀스 주입 방지
     * - 큰따옴표("): JSON/프롬프트 구조 탈출 방지
     * - 줄바꿈(\n, \r): 프롬프트 구조 변조 방지
     * - 백틱(`): 코드 블록 주입 방지
     * - 중괄호({, }): 템플릿 변수 주입 방지
     *
     * @param input 사용자 입력 문자열
     * @return 새니타이징된 문자열 또는 null
     */
    public static String sanitizeUserInput(String input) {
        if (input == null) {
            return null;
        }
        return input
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", " ")
            .replace("\r", " ")
            .replace("`", "'")
            .replace("{", "(")
            .replace("}", ")");
    }

    /**
     * 사용자 입력 새니타이징 후 길이 제한 적용
     *
     * @param input 사용자 입력 문자열
     * @param maxLength 최대 길이
     * @return 새니타이징 및 길이 제한된 문자열
     */
    public static String sanitizeAndTruncate(String input, int maxLength) {
        String sanitized = sanitizeUserInput(input);
        return truncate(sanitized, maxLength);
    }

    // ========== AI Native v4.0: IP 형식 검증 ==========

    /**
     * IPv4 형식 정규표현식 패턴
     * 예: 192.168.1.1, 10.0.0.1, 255.255.255.255
     */
    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    /**
     * IPv6 간이 형식 정규표현식 패턴 (축약형 포함)
     * 예: ::1, fe80::1, 2001:0db8:85a3::8a2e:0370:7334
     */
    private static final Pattern IPV6_PATTERN = Pattern.compile(
        "^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|" +
        "([0-9a-fA-F]{1,4}:){1,7}:|" +
        "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|" +
        "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|" +
        "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|" +
        "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|" +
        "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|" +
        "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|" +
        ":((:[0-9a-fA-F]{1,4}){1,7}|:)|" +
        "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|" +
        "::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|" +
        "([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$");

    /**
     * IP 형식이 유효한지 검사 (IPv4 또는 IPv6)
     *
     * AI Native v4.0: Zero Trust 필수 필드 검증
     * - 잘못된 IP 형식이 프롬프트에 포함되면 LLM 혼란 유발
     * - "999.999.999.999" 같은 잘못된 값을 걸러냄
     *
     * @param ip 검사할 IP 주소 문자열
     * @return 유효한 IPv4 또는 IPv6 형식이면 true
     */
    public static boolean isValidIpFormat(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        return IPV4_PATTERN.matcher(ip).matches() || IPV6_PATTERN.matcher(ip).matches();
    }

    /**
     * IP 주소를 검증하여 StringBuilder에 추가
     *
     * AI Native v4.0: IP 형식 검증 결과에 따른 라벨 표시
     * - 유효한 IP: "IP: 192.168.1.1"
     * - 유효하지 않은 형식: "IP: abc.def [INVALID_FORMAT]"
     * - 값 없음: "IP: NOT_PROVIDED [CRITICAL]"
     *
     * @param sb StringBuilder
     * @param ip IP 주소 문자열
     */
    public static void appendIpWithValidation(StringBuilder sb, String ip) {
        if (ip == null || ip.isEmpty()) {
            sb.append("IP: NOT_PROVIDED [CRITICAL]\n");
        } else if (!isValidIpFormat(ip)) {
            sb.append("IP: ").append(sanitizeUserInput(ip)).append(" [INVALID_FORMAT]\n");
        } else {
            sb.append("IP: ").append(sanitizeUserInput(ip)).append("\n");
        }
    }
}
