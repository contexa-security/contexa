package io.contexa.contexacoreenterprise.autonomous.validation;

import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AI가 생성한 SpEL 표현식 검증 서비스
 *
 * AI 정책 엔진(PolicyEvolutionEngine)이 생성한 SpEL 표현식이
 * 실제 Contexa 보안 시스템에서 실행 가능한지 검증합니다.
 *
 * 검증 항목:
 * 1. SpEL 구문 유효성
 * 2. 허용된 메서드/변수만 사용하는지 확인
 * 3. 보안 위험 패턴 탐지 (코드 인젝션 방지)
 *
 * @since 0.1.0-ALPHA
 */
@Slf4j
public class SpelValidationService {

    private final ExpressionParser parser = new SpelExpressionParser();

    // ========== 허용된 SpEL 변수 및 메서드 ==========

    /**
     * #trust 변수에서 허용된 메서드 (TrustSecurityExpressionRoot)
     * Hot Path 전용 - Redis에서 LLM Action 조회
     *
     * 주의: 점수 기반 메서드(levelExceeds, isLowRisk 등)는 제거됨
     * Action 기반 메서드(isAllowed, isBlocked 등)로 전환됨
     */
    private static final Set<String> TRUST_METHODS = Set.of(
        // 리소스/권한 기반 메서드
        "hasResourceAccess",      // #trust.hasResourceAccess('resource', 0.5)
        "hasTemporaryPermission", // #trust.hasTemporaryPermission('type')
        // LLM Action 기반 메서드 (Zero Trust) - 권장
        "isAllowed",              // #trust.isAllowed() - ALLOW 여부
        "isBlocked",              // #trust.isBlocked() - BLOCK 여부
        "needsChallenge",         // #trust.needsChallenge() - MFA 필요 여부
        "needsInvestigation",     // #trust.needsInvestigation() - INVESTIGATE/ESCALATE 여부
        "isMonitored",            // #trust.isMonitored() - MONITOR 여부
        "isPendingAnalysis",      // #trust.isPendingAnalysis() - 분석 미완료 여부
        "hasAction",              // #trust.hasAction('ALLOW') - 특정 action 여부
        "hasActionIn",            // #trust.hasActionIn('ALLOW', 'MONITOR') - 목록 내 action 여부
        "isAnalysisComplete",     // #trust.isAnalysisComplete() - 분석 완료 여부
        "requiresAnalysis"        // #trust.requiresAnalysis() - 분석 필요 여부
    );

    /**
     * #ai 변수에서 허용된 메서드 (RealtimeAISecurityExpressionRoot)
     * Cold Path 전용 - 실시간 AI 분석 (고위험 작업용)
     */
    private static final Set<String> AI_METHODS = Set.of(
        "analyzeFraud",               // #ai.analyzeFraud(#transaction)
        "detectAnomaly",              // #ai.detectAnomaly(#operation)
        "evaluateCriticalOperation",  // #ai.evaluateCriticalOperation(#context)
        "evaluateDataExfiltration",   // #ai.evaluateDataExfiltration(#dataAccess)
        "evaluatePrivilegeEscalation", // #ai.evaluatePrivilegeEscalation('ADMIN')
        "assessContext",              // #ai.assessContext().score
        "hasSafeBehavior"             // #ai.hasSafeBehavior(20.0)
    );

    /**
     * Spring Security 기본 메서드 (SecurityExpressionRoot)
     */
    private static final Set<String> SECURITY_METHODS = Set.of(
        // 역할 기반
        "hasRole",                // hasRole('ADMIN')
        "hasAnyRole",             // hasAnyRole('ADMIN', 'USER')
        // 권한 기반
        "hasAuthority",           // hasAuthority('READ_PRIVILEGE')
        "hasAnyAuthority",        // hasAnyAuthority('READ', 'WRITE')
        // 인증 상태
        "isAuthenticated",        // isAuthenticated()
        "isFullyAuthenticated",   // isFullyAuthenticated()
        "isAnonymous",            // isAnonymous()
        "isRememberMe",           // isRememberMe()
        // 전역 허용/거부
        "permitAll",              // permitAll()
        "denyAll"                 // denyAll()
    );

    /**
     * 허용된 SpEL 변수 이름
     */
    private static final Set<String> ALLOWED_VARIABLES = Set.of(
        "trust",          // #trust - TrustSecurityExpressionRoot
        "ai",             // #ai - RealtimeAISecurityExpressionRoot
        "principal",      // #principal - 현재 인증된 사용자
        "authentication", // #authentication - Authentication 객체
        "request",        // #request - HTTP 요청 (URL 정책용)
        // 메서드 파라미터 변수 (동적)
        "transaction",    // #transaction - 사기 분석용
        "operation",      // #operation - 이상 탐지용
        "context",        // #context - 중요 작업용
        "dataAccess",     // #dataAccess - 데이터 유출용
        "target",         // #target - 대상 객체
        "returnObject",   // #returnObject - @PostAuthorize용
        "filterObject"    // #filterObject - @PreFilter/@PostFilter용
    );

    /**
     * 보안 위험 패턴 - 코드 인젝션 방지
     */
    private static final List<Pattern> DANGEROUS_PATTERNS = List.of(
        // 시스템 명령 실행
        Pattern.compile("T\\s*\\(\\s*java\\.lang\\.Runtime\\s*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("T\\s*\\(\\s*java\\.lang\\.ProcessBuilder\\s*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.exec\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.getRuntime\\s*\\(", Pattern.CASE_INSENSITIVE),
        // 파일 시스템 접근
        Pattern.compile("T\\s*\\(\\s*java\\.io\\.", Pattern.CASE_INSENSITIVE),
        Pattern.compile("T\\s*\\(\\s*java\\.nio\\.", Pattern.CASE_INSENSITIVE),
        // 리플렉션 악용
        Pattern.compile("\\.getClass\\s*\\(\\s*\\)\\.forName", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.getDeclaredMethod", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.invoke\\s*\\(", Pattern.CASE_INSENSITIVE),
        // 네트워크 접근
        Pattern.compile("T\\s*\\(\\s*java\\.net\\.", Pattern.CASE_INSENSITIVE),
        // 스크립트 엔진
        Pattern.compile("ScriptEngine", Pattern.CASE_INSENSITIVE),
        Pattern.compile("javax\\.script", Pattern.CASE_INSENSITIVE),
        // 위험한 Spring 표현식
        Pattern.compile("new\\s+[A-Z]", Pattern.CASE_INSENSITIVE), // 객체 생성
        Pattern.compile("T\\s*\\(", Pattern.CASE_INSENSITIVE)       // Type 참조 (제한적 허용)
    );

    /**
     * 메서드 호출 패턴
     */
    private static final Pattern METHOD_CALL_PATTERN = Pattern.compile(
        "#?(\\w+)\\s*\\.\\s*(\\w+)\\s*\\("
    );

    /**
     * 변수 참조 패턴
     */
    private static final Pattern VARIABLE_PATTERN = Pattern.compile(
        "#(\\w+)"
    );

    /**
     * 단독 메서드 호출 패턴 (hasRole, isAuthenticated 등)
     */
    private static final Pattern STANDALONE_METHOD_PATTERN = Pattern.compile(
        "\\b(hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|isAuthenticated|" +
        "isFullyAuthenticated|isAnonymous|isRememberMe|permitAll|denyAll)\\s*\\("
    );

    // ========== 검증 결과 클래스 ==========

    /**
     * SpEL 검증 결과
     */
    public record ValidationResult(
        boolean valid,
        String expression,
        List<String> errors,
        List<String> warnings
    ) {
        public static ValidationResult valid(String expression) {
            return new ValidationResult(true, expression, List.of(), List.of());
        }

        public static ValidationResult valid(String expression, List<String> warnings) {
            return new ValidationResult(true, expression, List.of(), warnings);
        }

        public static ValidationResult invalid(String expression, String error) {
            return new ValidationResult(false, expression, List.of(error), List.of());
        }

        public static ValidationResult invalid(String expression, List<String> errors) {
            return new ValidationResult(false, expression, errors, List.of());
        }
    }

    // ========== 검증 메서드 ==========

    /**
     * SpEL 표현식 종합 검증
     *
     * @param spelExpression 검증할 SpEL 표현식
     * @return 검증 결과
     */
    public ValidationResult validate(String spelExpression) {
        if (spelExpression == null || spelExpression.isBlank()) {
            return ValidationResult.invalid(spelExpression, "SpEL 표현식이 비어있습니다");
        }

        String trimmed = spelExpression.trim();
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        // 1. 보안 위험 패턴 검사 (가장 먼저)
        ValidationResult securityCheck = checkSecurityPatterns(trimmed);
        if (!securityCheck.valid()) {
            return securityCheck;
        }

        // 2. SpEL 구문 검증
        ValidationResult syntaxCheck = validateSyntax(trimmed);
        if (!syntaxCheck.valid()) {
            return syntaxCheck;
        }

        // 3. 허용된 변수 검증
        List<String> variableErrors = validateVariables(trimmed);
        errors.addAll(variableErrors);

        // 4. 허용된 메서드 검증
        List<String> methodErrors = validateMethods(trimmed);
        errors.addAll(methodErrors);

        // 5. 경고 수집 (최적화 제안)
        warnings.addAll(collectWarnings(trimmed));

        if (errors.isEmpty()) {
            log.debug("SpEL 검증 성공: {}", trimmed);
            return ValidationResult.valid(trimmed, warnings);
        } else {
            log.warn("SpEL 검증 실패: {} - 오류: {}", trimmed, errors);
            return ValidationResult.invalid(trimmed, errors);
        }
    }

    /**
     * 보안 위험 패턴 검사
     */
    private ValidationResult checkSecurityPatterns(String expression) {
        for (Pattern pattern : DANGEROUS_PATTERNS) {
            Matcher matcher = pattern.matcher(expression);
            if (matcher.find()) {
                String matched = matcher.group();
                log.error("보안 위험 패턴 탐지: '{}' in expression: {}", matched, expression);
                return ValidationResult.invalid(
                    expression,
                    "보안 위험: 금지된 패턴 '" + matched + "' 이(가) 탐지되었습니다"
                );
            }
        }
        return ValidationResult.valid(expression);
    }

    /**
     * SpEL 구문 검증
     */
    private ValidationResult validateSyntax(String expression) {
        try {
            parser.parseExpression(expression);
            return ValidationResult.valid(expression);
        } catch (SpelParseException e) {
            return ValidationResult.invalid(
                expression,
                "SpEL 구문 오류: " + e.getMessage()
            );
        }
    }

    /**
     * 변수 검증
     */
    private List<String> validateVariables(String expression) {
        List<String> errors = new ArrayList<>();
        Matcher matcher = VARIABLE_PATTERN.matcher(expression);

        while (matcher.find()) {
            String variable = matcher.group(1);
            if (!ALLOWED_VARIABLES.contains(variable)) {
                errors.add("허용되지 않은 변수: #" + variable);
            }
        }

        return errors;
    }

    /**
     * 메서드 검증
     */
    private List<String> validateMethods(String expression) {
        List<String> errors = new ArrayList<>();

        // 1. 객체.메서드() 패턴 검증
        Matcher methodMatcher = METHOD_CALL_PATTERN.matcher(expression);
        while (methodMatcher.find()) {
            String object = methodMatcher.group(1);
            String method = methodMatcher.group(2);

            if (!isAllowedMethodCall(object, method)) {
                errors.add("허용되지 않은 메서드 호출: " + object + "." + method + "()");
            }
        }

        // 2. 단독 메서드 호출 (hasRole 등)은 항상 허용
        // STANDALONE_METHOD_PATTERN은 이미 SECURITY_METHODS에 포함되어 있으므로 추가 검증 불필요

        return errors;
    }

    /**
     * 메서드 호출이 허용되는지 확인
     */
    private boolean isAllowedMethodCall(String object, String method) {
        // #trust.xxx()
        if ("trust".equals(object)) {
            return TRUST_METHODS.contains(method);
        }
        // #ai.xxx()
        if ("ai".equals(object)) {
            return AI_METHODS.contains(method);
        }
        // assessContext().score (체인 호출)
        if ("assessContext".equals(object) && "score".equals(method)) {
            return true;
        }
        // 기본 Spring Security 메서드
        if (SECURITY_METHODS.contains(object)) {
            return true;
        }
        // 허용된 변수에 대한 속성 접근
        if (ALLOWED_VARIABLES.contains(object)) {
            return true;
        }

        return false;
    }

    /**
     * 경고 수집 (최적화 제안)
     */
    private List<String> collectWarnings(String expression) {
        List<String> warnings = new ArrayList<>();

        // Cold Path 메서드 사용 경고
        if (expression.contains("#ai.")) {
            warnings.add("주의: #ai 메서드는 실시간 AI 호출로 응답 시간이 길어질 수 있습니다 (Cold Path)");
        }

        // 복잡한 표현식 경고
        if (expression.length() > 200) {
            warnings.add("주의: 복잡한 SpEL 표현식은 성능에 영향을 줄 수 있습니다");
        }

        // 중첩 조건 경고
        long andCount = expression.chars().filter(ch -> ch == '&').count();
        long orCount = expression.chars().filter(ch -> ch == '|').count();
        if (andCount + orCount > 5) {
            warnings.add("주의: 조건이 복잡합니다. 정책 분리를 고려하세요");
        }

        return warnings;
    }

    // ========== 유틸리티 메서드 ==========

    /**
     * 허용된 #trust 메서드 목록 반환
     */
    public Set<String> getAllowedTrustMethods() {
        return Collections.unmodifiableSet(TRUST_METHODS);
    }

    /**
     * 허용된 #ai 메서드 목록 반환
     */
    public Set<String> getAllowedAIMethods() {
        return Collections.unmodifiableSet(AI_METHODS);
    }

    /**
     * 허용된 Spring Security 메서드 목록 반환
     */
    public Set<String> getAllowedSecurityMethods() {
        return Collections.unmodifiableSet(SECURITY_METHODS);
    }

    /**
     * 허용된 변수 목록 반환
     */
    public Set<String> getAllowedVariables() {
        return Collections.unmodifiableSet(ALLOWED_VARIABLES);
    }

    /**
     * AI 프롬프트용 SpEL API 문서 생성
     */
    public String generateApiDocumentation() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Contexa SpEL API 문서 ===\n\n");

        sb.append("## #trust 변수 (Hot Path - Redis 조회)\n");
        sb.append("LLM 분석 결과(Action) 기반 빠른 인가 결정:\n");
        for (String method : TRUST_METHODS) {
            sb.append("  - #trust.").append(method).append("()\n");
        }

        sb.append("\n## #ai 변수 (Cold Path - 실시간 AI 분석)\n");
        sb.append("고위험 작업용 실시간 AI 분석:\n");
        for (String method : AI_METHODS) {
            sb.append("  - #ai.").append(method).append("()\n");
        }

        sb.append("\n## Spring Security 기본 메서드\n");
        for (String method : SECURITY_METHODS) {
            sb.append("  - ").append(method).append("()\n");
        }

        sb.append("\n## 허용된 변수\n");
        for (String variable : ALLOWED_VARIABLES) {
            sb.append("  - #").append(variable).append("\n");
        }

        return sb.toString();
    }
}
