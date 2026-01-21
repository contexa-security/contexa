package io.contexa.contexacoreenterprise.autonomous.validation;

import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class SpelValidationService {

    private final ExpressionParser parser = new SpelExpressionParser();

    private static final Set<String> TRUST_METHODS = Set.of(
        
        "hasResourceAccess",      
        "hasTemporaryPermission", 
        
        "isAllowed",              
        "isBlocked",              
        "needsChallenge",         
        "needsInvestigation",     
        "isMonitored",            
        "isPendingAnalysis",      
        "hasAction",              
        "hasActionIn",            
        "isAnalysisComplete",     
        "requiresAnalysis"        
    );

    private static final Set<String> AI_METHODS = Set.of(
        "analyzeFraud",               
        "detectAnomaly",              
        "evaluateCriticalOperation",  
        "evaluateDataExfiltration",   
        "evaluatePrivilegeEscalation", 
        "assessContext",              
        "hasSafeBehavior"             
    );

    private static final Set<String> SECURITY_METHODS = Set.of(
        
        "hasRole",                
        "hasAnyRole",             
        
        "hasAuthority",           
        "hasAnyAuthority",        
        
        "isAuthenticated",        
        "isFullyAuthenticated",   
        "isAnonymous",            
        "isRememberMe",           
        
        "permitAll",              
        "denyAll"                 
    );

    private static final Set<String> ALLOWED_VARIABLES = Set.of(
        "trust",          
        "ai",             
        "principal",      
        "authentication", 
        "request",        
        
        "transaction",    
        "operation",      
        "context",        
        "dataAccess",     
        "target",         
        "returnObject",   
        "filterObject"    
    );

    private static final List<Pattern> DANGEROUS_PATTERNS = List.of(
        
        Pattern.compile("T\\s*\\(\\s*java\\.lang\\.Runtime\\s*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("T\\s*\\(\\s*java\\.lang\\.ProcessBuilder\\s*\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.exec\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.getRuntime\\s*\\(", Pattern.CASE_INSENSITIVE),
        
        Pattern.compile("T\\s*\\(\\s*java\\.io\\.", Pattern.CASE_INSENSITIVE),
        Pattern.compile("T\\s*\\(\\s*java\\.nio\\.", Pattern.CASE_INSENSITIVE),
        
        Pattern.compile("\\.getClass\\s*\\(\\s*\\)\\.forName", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.getDeclaredMethod", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.invoke\\s*\\(", Pattern.CASE_INSENSITIVE),
        
        Pattern.compile("T\\s*\\(\\s*java\\.net\\.", Pattern.CASE_INSENSITIVE),
        
        Pattern.compile("ScriptEngine", Pattern.CASE_INSENSITIVE),
        Pattern.compile("javax\\.script", Pattern.CASE_INSENSITIVE),
        
        Pattern.compile("new\\s+[A-Z]", Pattern.CASE_INSENSITIVE), 
        Pattern.compile("T\\s*\\(", Pattern.CASE_INSENSITIVE)       
    );

    private static final Pattern METHOD_CALL_PATTERN = Pattern.compile(
        "#?(\\w+)\\s*\\.\\s*(\\w+)\\s*\\("
    );

    private static final Pattern VARIABLE_PATTERN = Pattern.compile(
        "#(\\w+)"
    );

    private static final Pattern STANDALONE_METHOD_PATTERN = Pattern.compile(
        "\\b(hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|isAuthenticated|" +
        "isFullyAuthenticated|isAnonymous|isRememberMe|permitAll|denyAll)\\s*\\("
    );

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

    public ValidationResult validate(String spelExpression) {
        if (spelExpression == null || spelExpression.isBlank()) {
            return ValidationResult.invalid(spelExpression, "SpEL 표현식이 비어있습니다");
        }

        String trimmed = spelExpression.trim();
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        ValidationResult securityCheck = checkSecurityPatterns(trimmed);
        if (!securityCheck.valid()) {
            return securityCheck;
        }

        ValidationResult syntaxCheck = validateSyntax(trimmed);
        if (!syntaxCheck.valid()) {
            return syntaxCheck;
        }

        List<String> variableErrors = validateVariables(trimmed);
        errors.addAll(variableErrors);

        List<String> methodErrors = validateMethods(trimmed);
        errors.addAll(methodErrors);

        warnings.addAll(collectWarnings(trimmed));

        if (errors.isEmpty()) {
                        return ValidationResult.valid(trimmed, warnings);
        } else {
            log.warn("SpEL 검증 실패: {} - 오류: {}", trimmed, errors);
            return ValidationResult.invalid(trimmed, errors);
        }
    }

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

    private List<String> validateMethods(String expression) {
        List<String> errors = new ArrayList<>();

        Matcher methodMatcher = METHOD_CALL_PATTERN.matcher(expression);
        while (methodMatcher.find()) {
            String object = methodMatcher.group(1);
            String method = methodMatcher.group(2);

            if (!isAllowedMethodCall(object, method)) {
                errors.add("허용되지 않은 메서드 호출: " + object + "." + method + "()");
            }
        }

        return errors;
    }

    private boolean isAllowedMethodCall(String object, String method) {
        
        if ("trust".equals(object)) {
            return TRUST_METHODS.contains(method);
        }
        
        if ("ai".equals(object)) {
            return AI_METHODS.contains(method);
        }
        
        if ("assessContext".equals(object) && "score".equals(method)) {
            return true;
        }
        
        if (SECURITY_METHODS.contains(object)) {
            return true;
        }
        
        if (ALLOWED_VARIABLES.contains(object)) {
            return true;
        }

        return false;
    }

    private List<String> collectWarnings(String expression) {
        List<String> warnings = new ArrayList<>();

        if (expression.contains("#ai.")) {
            warnings.add("주의: #ai 메서드는 실시간 AI 호출로 응답 시간이 길어질 수 있습니다 (Cold Path)");
        }

        if (expression.length() > 200) {
            warnings.add("주의: 복잡한 SpEL 표현식은 성능에 영향을 줄 수 있습니다");
        }

        long andCount = expression.chars().filter(ch -> ch == '&').count();
        long orCount = expression.chars().filter(ch -> ch == '|').count();
        if (andCount + orCount > 5) {
            warnings.add("주의: 조건이 복잡합니다. 정책 분리를 고려하세요");
        }

        return warnings;
    }

    public Set<String> getAllowedTrustMethods() {
        return Collections.unmodifiableSet(TRUST_METHODS);
    }

    public Set<String> getAllowedAIMethods() {
        return Collections.unmodifiableSet(AI_METHODS);
    }

    public Set<String> getAllowedSecurityMethods() {
        return Collections.unmodifiableSet(SECURITY_METHODS);
    }

    public Set<String> getAllowedVariables() {
        return Collections.unmodifiableSet(ALLOWED_VARIABLES);
    }

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
