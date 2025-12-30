package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Optional;

/**
 * Layer 1: 초고속 필터링 프롬프트 템플릿 (최적화 버전)
 *
 * BeanOutputConverter 제거로 프롬프트 크기 대폭 감소:
 * - 변경 전: 1800+ 토큰 (JSON Schema 포함)
 * - 변경 후: 300 토큰 (85% 감소!)
 *
 * 예상 성능:
 * - TinyLlama: 2-3초 → 50-100ms (40-60배 개선!)
 *
 * 98%의 이벤트를 50-100ms 내에 처리하는 첫 번째 방어선
 */
@Slf4j
public class Layer1PromptTemplate {

    private final TieredStrategyProperties tieredStrategyProperties;

    @Autowired
    public Layer1PromptTemplate(
            @Autowired(required = false) TieredStrategyProperties tieredStrategyProperties) {
        this.tieredStrategyProperties = tieredStrategyProperties != null
            ? tieredStrategyProperties : new TieredStrategyProperties();
    }

    /**
     * Layer1 프롬프트 생성 (기본 버전 - 하위 호환)
     */
    public String buildPrompt(SecurityEvent event, String knownPatterns) {
        return buildPrompt(event, knownPatterns, null);
    }

    /**
     * Layer1 프롬프트 생성 (AI Native - Phase 5 신뢰 데이터 중심)
     *
     * Phase 5 핵심 원칙:
     * - 유효한 데이터만 프롬프트에 포함 (unknown/none 제외)
     * - LLM이 정확한 판단을 할 수 있도록 신뢰할 수 있는 정보만 제공
     * - 데이터 부족 시 명시적으로 "정보 부족" 표시
     *
     * @param event 보안 이벤트
     * @param knownPatterns 알려진 위협 패턴
     * @param baselineContext 사용자 baseline 컨텍스트
     * @return LLM 프롬프트 문자열
     */
    public String buildPrompt(SecurityEvent event, String knownPatterns, String baselineContext) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Security event analysis. Respond in JSON only.\n\n");

        // Zero Trust Rule Injection
        prompt.append("CRITICAL ZERO TRUST RULES:\n");
        prompt.append("1. 'NO USER BASELINE' means the user is unknown. Treat with EXTREME CAUTION.\n");
        prompt.append("2. DO NOT assume an IP is 'established' or 'trusted' unless explicitly stated in KNOWN THREATS or METADATA.\n");
        prompt.append("3. If you have NO baseline and NO past history, prefer ESCALATE (E) or CHALLENGE (C) over ALLOW (A), unless the request is clearly harmless public data.\n\n");

        // 1. 핵심 이벤트 정보 (유효한 데이터만)
        // AI Native v4.1.0: Severity 제거 - LLM이 원시 데이터로 직접 판단
        prompt.append("=== EVENT ===\n");
        appendIfValid(prompt, "User", event.getUserId());
        // AI Native: 기본값 "Security event"는 정보량 없음 - 유의미한 description만 출력
        // AI Native v4.0: equalsIgnoreCase로 대소문자 무관 비교
        String description = event.getDescription();
        if (description != null && !description.equalsIgnoreCase("Security event")) {
            appendIfValid(prompt, "Description", description);
        }

        // AI Native v4.0: 원시 메트릭 제공 (Severity 대신 LLM이 직접 위험도 평가)
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            appendMetadataIfPresent(prompt, metadata, "auth.failure_count", "FailureCount");
            // AI Native v5.0: TrustScore 출처 확인됨
            // 설정: ZeroTrustEventListener.java:315, KafkaSecurityEventCollector.java:644
            // 계산: trustScore = 1.0 - threatScore (ZeroTrustSecurityService.java:82)
            // 근원: Redis threat_score:{userId}
            // 범위: 0.0 ~ 1.0 (명확함)
            appendMetadataIfPresent(prompt, metadata, "authz.trustScore", "TrustScore");
        }

        // 2. 네트워크 정보 (Zero Trust: 항상 출력 - 누락 필드 명시)
        prompt.append("\n=== NETWORK ===\n");
        // IP는 필수 필드 - 없으면 CRITICAL 경고
        appendFieldWithNullCheck(prompt, "IP", event.getSourceIp(), true);
        // SessionId는 필수 필드 - 없으면 CRITICAL 경고
        appendFieldWithNullCheck(prompt, "SessionId", event.getSessionId(), true);
        // UserAgent는 선택적 필드
        String userAgent = event.getUserAgent();
        if (isValidData(userAgent)) {
            prompt.append("UserAgent: ").append(summarizeUserAgent(userAgent)).append("\n");
        } else {
            prompt.append("UserAgent: NOT_PROVIDED\n");
        }

        // 3. 유효한 추가 컨텍스트만 포함
        String validContext = buildValidContextSection(event);
        if (!validContext.isEmpty()) {
            prompt.append("\n=== CONTEXT ===\n");
            prompt.append(validContext);
        }

        // 5. 알려진 위협 패턴 (항상 출력 - Zero Trust)
        prompt.append("\n=== KNOWN THREATS ===\n");
        if (isValidPatterns(knownPatterns)) {
            String sanitizedPatterns = PromptTemplateUtils.sanitizeUserInput(knownPatterns);
            prompt.append(sanitizedPatterns).append("\n");
        } else if (knownPatterns != null && knownPatterns.startsWith("[")) {
            // 상태 메시지 (SERVICE_UNAVAILABLE, NO_DATA, ERROR)
            prompt.append(knownPatterns).append("\n");
        } else {
            prompt.append("[NO_DATA] No known threat patterns available\n");
        }

        // 6. Baseline 정보 (항상 출력 - Zero Trust)
        prompt.append("\n=== USER BASELINE ===\n");
        if (isValidBaseline(baselineContext)) {
            String sanitizedBaseline = PromptTemplateUtils.sanitizeUserInput(baselineContext);
            prompt.append(summarizeBaseline(sanitizedBaseline)).append("\n");
        } else if (baselineContext != null && baselineContext.startsWith("[")) {
            // 상태 메시지 (SERVICE_UNAVAILABLE, NO_USER_ID, NO_DATA)
            prompt.append(baselineContext).append("\n");
        } else {
            prompt.append("[NEW_USER] No baseline established for this user\n");
            prompt.append("CAUTION: Cannot compare against historical patterns\n");
        }

        // 7. 데이터 품질 평가 (Zero Trust v6.0: baseline 포함 평가)
        // 이전 문제: 7/10 표시가 LLM에게 "70% 충분" 오해 유발
        // 수정: baseline을 CRITICAL 필드로 포함, 정확한 점수 계산
        prompt.append("\n=== DATA QUALITY ===\n");
        prompt.append(PromptTemplateUtils.buildDataQualitySection(event, baselineContext));

        // 8. 응답 형식 (Zero Trust v6.0 - confidence 제약 조건 추가)
        prompt.append("""

            === ACTIONS ===
            A (ALLOW): Permit the request
            B (BLOCK): Deny the request
            C (CHALLENGE): Request additional verification (MFA)
            E (ESCALATE): Forward to Layer 2 analysis

            === CONFIDENCE RULES ===
            - If NO USER BASELINE exists: c MUST be <= 0.5 (cannot be certain without historical comparison)
            - If CRITICAL fields (sourceIp, sessionId, userId) are missing: c MUST be <= 0.3
            - confidence=1.0 requires: baseline exists AND no anomalies detected AND all critical fields present

            === RESPONSE FORMAT ===
            {"r":<0-1>,"c":<0-1>,"a":"A|B|C|E","d":"<reason>"}

            r: Your risk assessment (0=safe, 1=critical threat)
            c: Your confidence level (0=uncertain, 1=certain) - FOLLOW CONFIDENCE RULES ABOVE
            a: Your action decision
            d: Brief reasoning (max 20 tokens)
            """);

        return prompt.toString();
    }

    /**
     * 데이터가 유효한지 검사 (null, empty, "unknown" 제외)
     * PromptTemplateUtils로 위임
     */
    private boolean isValidData(String value) {
        return PromptTemplateUtils.isValidData(value);
    }

    /**
     * 유효한 데이터만 프롬프트에 추가 (기존 메서드 - 선택적 필드용)
     *
     * AI Native v3.3.0: 프롬프트 인젝션 방어
     * - 사용자 입력값은 sanitizeUserInput()을 통해 새니타이징
     */
    private void appendIfValid(StringBuilder sb, String label, String value) {
        if (isValidData(value)) {
            String sanitized = PromptTemplateUtils.sanitizeUserInput(value);
            sb.append(label).append(": ").append(sanitized).append("\n");
        }
    }

    /**
     * 필드를 프롬프트에 추가 (Zero Trust - null 필드 명시적 표현)
     *
     * AI Native 원칙:
     * - LLM이 "데이터 없음"을 인식할 수 있도록 NOT_PROVIDED 명시
     * - 필수 필드(isCritical=true)가 없으면 검증 데이터 부재 경고
     *
     * AI Native v3.3.0: 프롬프트 인젝션 방어
     * - 사용자 입력값은 sanitizeUserInput()을 통해 새니타이징
     *
     * @param sb StringBuilder
     * @param label 필드 라벨
     * @param value 필드 값
     * @param isCritical 필수 필드 여부 (true면 NOT_PROVIDED + 경고)
     */
    private void appendFieldWithNullCheck(StringBuilder sb, String label, String value, boolean isCritical) {
        if (isValidData(value)) {
            String sanitized = PromptTemplateUtils.sanitizeUserInput(value);
            sb.append(label).append(": ").append(sanitized).append("\n");
        } else if (isCritical) {
            // Zero Trust: 필수 필드 부재 명시
            sb.append(label).append(": NOT_PROVIDED [CRITICAL: Missing verification data]\n");
        } else {
            sb.append(label).append(": NOT_PROVIDED\n");
        }
    }

    /**
     * UserAgent 요약 (너무 길면 축약)
     * Truncation 정책은 TieredStrategyProperties에서 관리
     *
     * AI Native v3.3.0: 프롬프트 인젝션 방어
     * - UserAgent는 사용자가 조작 가능한 헤더이므로 새니타이징 필수
     */
    private String summarizeUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }
        // 프롬프트 인젝션 방어: 새니타이징 후 truncation
        String sanitized = PromptTemplateUtils.sanitizeUserInput(userAgent);
        int maxLength = tieredStrategyProperties.getTruncation().getLayer1().getUserAgent();
        if (sanitized.length() > maxLength) {
            return sanitized.substring(0, maxLength - 3) + "...";
        }
        return sanitized;
    }

    /**
     * 알려진 패턴이 실제로 유효한지 검사
     *
     * Zero Trust: 상태 메시지는 유효한 데이터가 아님
     * - [SERVICE_UNAVAILABLE]: 서비스 미설정
     * - [NO_DATA]: 데이터 없음
     * - [ERROR]: 에러 발생
     */
    private boolean isValidPatterns(String patterns) {
        if (patterns == null || patterns.isEmpty()) {
            return false;
        }
        // 상태 메시지는 유효한 데이터가 아님
        if (patterns.startsWith("[SERVICE_UNAVAILABLE]") ||
            patterns.startsWith("[NO_DATA]") ||
            patterns.startsWith("[ERROR]")) {
            return false;
        }
        return !patterns.equalsIgnoreCase("none")
            && !patterns.contains("Not available");
    }

    /**
     * Baseline 정보가 실제로 유효한지 검사
     *
     * Zero Trust 원칙:
     * - 상태 메시지는 유효한 데이터가 아님
     * - CRITICAL 경고가 포함된 신규 사용자 메시지는 반드시 출력
     * - LLM이 신규 사용자에 대한 보수적 판단을 할 수 있도록 함
     */
    private boolean isValidBaseline(String baseline) {
        if (baseline == null || baseline.isEmpty()) {
            return false;
        }
        // Zero Trust: 상태 메시지는 유효한 데이터가 아님
        if (baseline.startsWith("[SERVICE_UNAVAILABLE]") ||
            baseline.startsWith("[NO_USER_ID]") ||
            baseline.startsWith("[NO_DATA]")) {
            return false;
        }
        // Zero Trust: CRITICAL 경고가 포함된 신규 사용자 메시지는 반드시 출력
        if (baseline.contains("CRITICAL") || baseline.contains("NO USER BASELINE")) {
            return true;  // 신규 사용자 경고는 반드시 LLM에게 전달
        }
        // 기타 무의미한 기본값만 제외 (case-insensitive)
        return !baseline.equalsIgnoreCase("Not available")
            && !baseline.equalsIgnoreCase("none")
            && !baseline.equalsIgnoreCase("N/A");
    }

    /**
     * 유효한 컨텍스트 정보만 빌드
     */
    private String buildValidContextSection(SecurityEvent event) {
        StringBuilder context = new StringBuilder();

        // 시간 정보 (ISO 8601 형식으로 raw 데이터 제공 - AI Native)
        // LLM이 시간대의 위험도를 직접 판단
        if (event.getTimestamp() != null) {
            context.append("Timestamp: ").append(event.getTimestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\n");
        }

        // metadata에서 유효한 정보만 추출
        // AI Native v3.0: null 필드 명시적 NOT_PROVIDED 표현 - LLM이 누락 인식
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && !metadata.isEmpty()) {
            // 세션 관련 정보 (boolean 값은 의미 있음)
            // 정의: Redis 세션 메타데이터 존재 여부 (HCADContext.java 라인 56)
            Object isNewSession = metadata.get("isNewSession");
            if (isNewSession instanceof Boolean) {
                context.append("NewSession: ").append(isNewSession).append("\n");
            } else {
                context.append("NewSession: NOT_PROVIDED\n");
            }

            // AI Native v3.0: isNewDevice는 User-Agent 비교 기반 - 스푸핑 가능하므로 경고 라벨 추가
            // 공격자가 피해자의 User-Agent 복사 시 isNewDevice=false 반환 → LLM 오판단 가능
            Object isNewDevice = metadata.get("isNewDevice");
            if (isNewDevice instanceof Boolean) {
                context.append("NewDevice(spoofable): ").append(isNewDevice).append("\n");
            } else {
                context.append("NewDevice(spoofable): NOT_PROVIDED\n");
            }

            // 요청 빈도 (숫자 값)
            // 정의: 최근 5분간 요청 수 (HCADContext.java 라인 54, 506)
            Object recentReqs = metadata.get("recentRequestCount");
            if (recentReqs instanceof Number) {
                context.append("RecentRequests(5min): ").append(recentReqs).append("\n");
            } else {
                context.append("RecentRequests(5min): NOT_PROVIDED\n");
            }
        } else {
            // metadata 자체가 null이거나 비어있으면 모든 필드 NOT_PROVIDED
            context.append("NewSession: NOT_PROVIDED\n");
            context.append("NewDevice(spoofable): NOT_PROVIDED\n");
            context.append("RecentRequests(5min): NOT_PROVIDED\n");
        }

        return context.toString();
    }

    /**
     * 데이터 품질 점수 계산 (0-10)
     * LLM이 판단의 신뢰도를 조절하는 데 참고
     * PromptTemplateUtils로 위임
     */
    private int calculateDataQuality(SecurityEvent event) {
        return PromptTemplateUtils.calculateDataQuality(event);
    }

    // AI Native 원칙: buildSessionTimeContext(), getTimeContext() 제거
    // 규칙 기반 시간대 분류 ("EARLY_MORNING", "NIGHT" 등)는 AI Native 위반
    // buildValidContextSection()에서 raw 시간 데이터만 제공 (hour, dayOfWeek)
    // LLM이 시간 변수의 위험도를 직접 판단

    /**
     * Payload 요약 (Truncation 정책 적용)
     *
     * AI Native v3.3.0: 프롬프트 인젝션 방어
     * - Payload는 사용자가 직접 조작하는 요청 본문이므로 새니타이징 필수
     */
    private String summarizePayload(String payload) {
        if (payload == null || payload.isEmpty()) {
            return "empty";
        }

        // 프롬프트 인젝션 방어: 새니타이징 후 truncation
        String sanitized = PromptTemplateUtils.sanitizeUserInput(payload);
        int maxLength = tieredStrategyProperties.getTruncation().getLayer1().getPayload();
        if (sanitized.length() > maxLength) {
            return sanitized.substring(0, maxLength) + "... (truncated)";
        }

        return sanitized;
    }

    /**
     * Phase 3: Baseline Context 단순화 (Truncation 정책 적용)
     * Phase 2-7: null -> N/A 명시적 표현
     *
     * 원본 baseline context를 압축하여 핵심 정보만 추출합니다.
     * 예: "Normal: office-IP, morning-login, CREATE/UPDATE ops"
     *
     * @param baselineContext 원본 baseline 컨텍스트
     * @return 압축된 baseline 문자열 또는 "N/A"
     */
    private String summarizeBaseline(String baselineContext) {
        if (baselineContext == null || baselineContext.isEmpty()) {
            return "N/A";
        }

        int maxLength = tieredStrategyProperties.getTruncation().getLayer1().getBaselineContext();
        if (baselineContext.length() > maxLength) {
            return baselineContext.substring(0, maxLength - 3) + "...";
        }

        return baselineContext;
    }

    /**
     * AI Native v4.1.0: metadata에서 원시 메트릭을 프롬프트에 추가
     *
     * Severity 대신 원시 데이터를 제공하여 LLM이 직접 위험도를 판단하도록 함
     * - failureCount, trustScore, riskScore 등 원시 값 제공
     * - LLM이 컨텍스트를 고려하여 독립적으로 판단
     *
     * @param sb StringBuilder
     * @param metadata 이벤트 메타데이터
     * @param metadataKey metadata에서 조회할 키
     * @param promptLabel 프롬프트에 표시할 라벨
     */
    private void appendMetadataIfPresent(StringBuilder sb, Map<String, Object> metadata, String metadataKey, String promptLabel) {
        if (metadata == null) {
            return;
        }
        Object value = metadata.get(metadataKey);
        if (value != null) {
            sb.append(promptLabel).append(": ").append(value).append("\n");
        }
    }
}