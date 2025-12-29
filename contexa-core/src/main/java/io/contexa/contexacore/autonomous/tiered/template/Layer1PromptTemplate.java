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

        // 1. 핵심 이벤트 정보 (유효한 데이터만)
        prompt.append("=== EVENT ===\n");
        appendIfValid(prompt, "Type", event.getEventType() != null ? event.getEventType().toString() : null);
        appendIfValid(prompt, "Severity", event.getSeverity() != null ? event.getSeverity().name() : null);
        appendIfValid(prompt, "User", event.getUserId());
        appendIfValid(prompt, "Description", event.getDescription());

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

        // 3. Authorization 정보 (metadata에서 추출 - 가장 중요한 컨텍스트)
        String authzInfo = buildAuthzSection(event);
        if (!authzInfo.isEmpty()) {
            prompt.append("\n=== AUTHORIZATION ===\n");
            prompt.append(authzInfo).append("\n");
        }

        // 4. 유효한 추가 컨텍스트만 포함
        String validContext = buildValidContextSection(event);
        if (!validContext.isEmpty()) {
            prompt.append("\n=== CONTEXT ===\n");
            prompt.append(validContext);
        }

        // 5. 알려진 위협 패턴 (실제 패턴이 있을 때만)
        if (isValidPatterns(knownPatterns)) {
            prompt.append("\n=== KNOWN THREATS ===\n");
            prompt.append(knownPatterns).append("\n");
        }

        // 6. Baseline 정보 (신뢰할 수 있는 데이터가 있을 때만)
        if (isValidBaseline(baselineContext)) {
            prompt.append("\n=== USER BASELINE ===\n");
            prompt.append(summarizeBaseline(baselineContext)).append("\n");
        }

        // 7. 데이터 품질 평가 (AI Native v3.1.0: 누락 필드 명시)
        // Zero Trust: 누락된 필드를 명시적으로 표시하여 LLM이 인식하도록 함
        prompt.append("\n=== DATA QUALITY ===\n");
        prompt.append(PromptTemplateUtils.buildDataQualitySection(event));

        // 8. 응답 형식 (AI Native v3.4.0 - 액션 우선 원칙 + 기준선 학습 연동)
        prompt.append("""

            === RESPONSE FORMAT ===
            {"r":<0-1>,"c":<0-1>,"a":"A|B|C|E","d":"<reason>"}
            a: YOUR FINAL DECISION (one of A/B/C/E) - Action is primary
            r: risk level supporting your action (0=safe, 1=attack) - for traceability
            c: your confidence in this decision (0-1, lower if data is limited)
            d: brief reason (max 20 tokens)

            === ACTION SELECTION RULES (MANDATORY) ===
            You MUST follow these rules when selecting action:

            1. A (ALLOW): Use ONLY when you are CERTAIN this is normal behavior
               - ALLOW means this pattern WILL BE LEARNED as the user's normal baseline
               - If you have ANY doubt about legitimacy, DO NOT use ALLOW
               - Wrong ALLOW = baseline pollution = future attacks may bypass detection

            2. B (BLOCK): Use when you are CERTAIN this is malicious/abnormal
               - Confirmed attack patterns, known threats, obvious malicious behavior
               - BLOCK patterns are NEVER learned into baseline

            3. C (CHALLENGE): Use when request SEEMS normal but you are NOT CERTAIN
               - This triggers MFA verification before proceeding
               - After MFA success, the pattern will be learned as normal
               - Use this for: new device, unusual time, slightly different pattern

            4. E (ESCALATE): Use when you CANNOT determine if normal or abnormal
               - Insufficient data for confident decision
               - Complex patterns requiring Layer2 deep analysis
               - Pattern deviates significantly from baseline but not obviously malicious

            CRITICAL WARNING:
            - If NOT CERTAIN, do NOT return A (ALLOW)
            - Use C (CHALLENGE) or E (ESCALATE) when you have ANY doubt
            - Your ALLOW decision directly affects user's baseline learning
            - A wrong ALLOW can permanently pollute the baseline

            === AI NATIVE PRINCIPLE ===
            - YOU decide the action. Risk score justifies your action.
            - If uncertain, ALWAYS use E (ESCALATE) - never guess.
            - Action takes precedence over risk score if they conflict.
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
     */
    private boolean isValidPatterns(String patterns) {
        return patterns != null && !patterns.isEmpty()
            && !patterns.equalsIgnoreCase("none")
            && !patterns.contains("Not available");
    }

    /**
     * Baseline 정보가 실제로 유효한지 검사
     *
     * Zero Trust 원칙:
     * - CRITICAL 경고가 포함된 신규 사용자 메시지는 반드시 출력
     * - LLM이 신규 사용자에 대한 보수적 판단을 할 수 있도록 함
     */
    private boolean isValidBaseline(String baseline) {
        if (baseline == null || baseline.isEmpty()) {
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
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && !metadata.isEmpty()) {
            // 세션 관련 정보 (boolean 값은 의미 있음)
            Object isNewSession = metadata.get("isNewSession");
            if (isNewSession instanceof Boolean) {
                context.append("NewSession: ").append(isNewSession).append("\n");
            }

            Object isNewDevice = metadata.get("isNewDevice");
            if (isNewDevice instanceof Boolean) {
                context.append("NewDevice: ").append(isNewDevice).append("\n");
            }

            // 요청 빈도 (숫자 값)
            Object recentReqs = metadata.get("recentRequestCount");
            if (recentReqs instanceof Number) {
                context.append("RecentRequests: ").append(recentReqs).append("\n");
            }
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

    /**
     * Phase 4: metadata에서 Authorization 정보 추출 (AI Native)
     *
     * AI Native 원칙: 유효한 데이터만 프롬프트에 포함
     * - null인 필드는 프롬프트에서 완전 생략
     * - "unknown" 기본값 사용 금지
     */
    private String buildAuthzSection(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return "";
        }

        StringBuilder authz = new StringBuilder();
        authz.append("Authz: ");

        // authz.resource - 접근 대상 리소스
        String authzResource = getStringFromMetadata(metadata, "authz.resource");
        if (authzResource != null) {
            authz.append("Resource=").append(authzResource).append(" | ");
        }

        // authz.action - 수행 액션
        String authzAction = getStringFromMetadata(metadata, "authz.action");
        if (authzAction != null) {
            authz.append("Action=").append(authzAction).append(" | ");
        }

        // authz.result - 인가 결과
        String authzResult = getStringFromMetadata(metadata, "authz.result");
        if (authzResult != null) {
            authz.append("Result=").append(authzResult).append(" | ");
        }

        // authz.reason - 거부 이유 (있는 경우)
        // AI Native v3.3.0: 프롬프트 인젝션 방어 적용
        String authzReason = getStringFromMetadata(metadata, "authz.reason");
        if (authzReason != null) {
            // 새니타이징 후 Truncation 적용
            authzReason = PromptTemplateUtils.sanitizeUserInput(authzReason);
            int maxAuthzReason = tieredStrategyProperties.getTruncation().getLayer1().getAuthzReason();
            if (authzReason.length() > maxAuthzReason) {
                authzReason = authzReason.substring(0, maxAuthzReason - 3) + "...";
            }
            authz.append("Reason=").append(authzReason).append(" | ");
        }

        // methodClass, methodName - 호출된 메서드 정보
        String methodClass = getStringFromMetadata(metadata, "methodClass");
        String methodName = getStringFromMetadata(metadata, "methodName");
        if (methodClass != null || methodName != null) {
            String classSimpleName = extractSimpleClassName(methodClass);
            String method = methodName != null ? methodName : "";
            if (classSimpleName != null && !method.isEmpty()) {
                authz.append("Method=").append(classSimpleName).append(".").append(method).append(" | ");
            } else if (classSimpleName != null) {
                authz.append("Class=").append(classSimpleName).append(" | ");
            } else if (!method.isEmpty()) {
                authz.append("Method=").append(method).append(" | ");
            }
        }

        String result = authz.toString();
        // 마지막 " | " 제거
        if (result.endsWith(" | ")) {
            result = result.substring(0, result.length() - 3);
        }

        // "Authz: " 만 있으면 빈 문자열 반환
        if ("Authz:".equals(result.trim())) {
            return "";
        }

        return result;
    }

    /**
     * metadata에서 문자열 값 안전하게 추출 (AI Native)
     * PromptTemplateUtils로 위임
     */
    private String getStringFromMetadata(Map<String, Object> metadata, String key) {
        return PromptTemplateUtils.getStringFromMetadata(metadata, key);
    }

    /**
     * 클래스 풀네임에서 심플 클래스명 추출 (AI Native)
     * PromptTemplateUtils로 위임
     */
    private String extractSimpleClassName(String fullClassName) {
        return PromptTemplateUtils.extractSimpleClassName(fullClassName);
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
}