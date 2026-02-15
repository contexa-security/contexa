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

    private static final Map<String, String> TRUST_METHOD_DOCS = Map.ofEntries(
        Map.entry("isAllowed", "#ai.isAllowed() -> boolean : LLM ALLOW verdict check"),
        Map.entry("isBlocked", "#ai.isBlocked() -> boolean : LLM BLOCK verdict check"),
        Map.entry("needsChallenge", "#ai.needsChallenge() -> boolean : MFA required (CHALLENGE)"),
        Map.entry("needsInvestigation", "#ai.needsInvestigation() -> boolean : Further investigation needed (INVESTIGATE/ESCALATE)"),
        Map.entry("isMonitored", "#ai.isMonitored() -> boolean : Monitoring mode (MONITOR)"),
        Map.entry("isPendingAnalysis", "#ai.isPendingAnalysis() -> boolean : Analysis incomplete (PENDING_ANALYSIS)"),
        Map.entry("hasAction", "#ai.hasAction(String action) -> boolean : Check specific LLM action"),
        Map.entry("hasActionIn", "#ai.hasActionIn(String... actions) -> boolean : Check if action is one of given values"),
        Map.entry("hasResourceAccess", "#ai.hasResourceAccess(String resourceId, double threshold) -> boolean : Resource-level access with trust threshold"),
        Map.entry("hasTemporaryPermission", "#ai.hasTemporaryPermission() -> boolean : Check temporary permission granted"),
        Map.entry("isAnalysisComplete", "#ai.isAnalysisComplete() -> boolean : Check if AI analysis is complete"),
        Map.entry("requiresAnalysis", "#ai.requiresAnalysis() -> boolean : Check if AI analysis is required")
    );

    private static final Set<String> AI_METHODS = Set.of(
        "analyzeFraud",
        "detectAnomaly",
        "evaluateCriticalOperation",
        "evaluateDataExfiltration",
        "evaluatePrivilegeEscalation",
        "hasSafeBehavior",
        "isAllowed",
        "isBlocked",
        "needsChallenge",
        "needsEscalation",
        "isPendingAnalysis",
        "hasAction",
        "hasActionIn",
        "hasActionOrDefault"
    );

    private static final Map<String, String> AI_METHOD_DOCS = Map.ofEntries(
        Map.entry("analyzeFraud", "#ai.analyzeFraud(#transaction) -> boolean : Fraud transaction analysis"),
        Map.entry("detectAnomaly", "#ai.detectAnomaly(String operation) -> boolean : Anomaly behavior detection"),
        Map.entry("evaluateCriticalOperation", "#ai.evaluateCriticalOperation(#context) -> boolean : Critical operation evaluation"),
        Map.entry("evaluateDataExfiltration", "#ai.evaluateDataExfiltration() -> boolean : Data exfiltration risk evaluation"),
        Map.entry("evaluatePrivilegeEscalation", "#ai.evaluatePrivilegeEscalation() -> boolean : Privilege escalation risk evaluation"),
        Map.entry("hasSafeBehavior", "#ai.hasSafeBehavior(double threshold) -> boolean : Behavior safety score check"),
        Map.entry("isAllowed", "#ai.isAllowed() -> boolean : Real-time AI ALLOW verdict"),
        Map.entry("isBlocked", "#ai.isBlocked() -> boolean : Real-time AI BLOCK verdict"),
        Map.entry("needsChallenge", "#ai.needsChallenge() -> boolean : Real-time AI CHALLENGE verdict"),
        Map.entry("needsEscalation", "#ai.needsEscalation() -> boolean : Real-time AI ESCALATE verdict"),
        Map.entry("isPendingAnalysis", "#ai.isPendingAnalysis() -> boolean : Analysis pending check"),
        Map.entry("hasAction", "#ai.hasAction(String action) -> boolean : Check specific AI action"),
        Map.entry("hasActionIn", "#ai.hasActionIn(String... actions) -> boolean : Check if action is one of given values"),
        Map.entry("hasActionOrDefault", "#ai.hasActionOrDefault(String action, String defaultAction) -> boolean : Check action with fallback")
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

    private static final Map<String, String> SECURITY_METHOD_DOCS = Map.of(
        "hasRole", "hasRole(String role) -> boolean : e.g. hasRole('ROLE_ADMIN')",
        "hasAnyRole", "hasAnyRole(String... roles) -> boolean : e.g. hasAnyRole('ROLE_ADMIN', 'ROLE_USER')",
        "hasAuthority", "hasAuthority(String authority) -> boolean : e.g. hasAuthority('WRITE')",
        "hasAnyAuthority", "hasAnyAuthority(String... authorities) -> boolean : e.g. hasAnyAuthority('READ', 'WRITE')",
        "isAuthenticated", "isAuthenticated() -> boolean : Check if user is authenticated",
        "isFullyAuthenticated", "isFullyAuthenticated() -> boolean : Fully authenticated (excludes Remember-Me)",
        "isAnonymous", "isAnonymous() -> boolean : Check if anonymous user",
        "isRememberMe", "isRememberMe() -> boolean : Check if Remember-Me authentication",
        "permitAll", "permitAll() -> boolean : Always allow",
        "denyAll", "denyAll() -> boolean : Always deny"
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

    private static final Set<String> SAFE_OBJECT_METHODS = Set.of(
        "equals", "hashCode", "toString", "compareTo",
        "isEmpty", "size", "length", "contains", "containsKey",
        "get", "getValue", "getName", "getType", "getId",
        "isPresent", "orElse"
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
            return ValidationResult.invalid(spelExpression, "SpEL expression is empty");
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
            log.error("SpEL validation failed: {} - errors: {}", trimmed, errors);
            return ValidationResult.invalid(trimmed, errors);
        }
    }

    private ValidationResult checkSecurityPatterns(String expression) {
        for (Pattern pattern : DANGEROUS_PATTERNS) {
            Matcher matcher = pattern.matcher(expression);
            if (matcher.find()) {
                String matched = matcher.group();
                log.error("Security risk pattern detected: '{}' in expression: {}", matched, expression);
                return ValidationResult.invalid(
                    expression,
                    "Security risk: prohibited pattern '" + matched + "' detected"
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
                "SpEL syntax error: " + e.getMessage()
            );
        }
    }

    private List<String> validateVariables(String expression) {
        List<String> errors = new ArrayList<>();
        Matcher matcher = VARIABLE_PATTERN.matcher(expression);

        while (matcher.find()) {
            String variable = matcher.group(1);
            if (!ALLOWED_VARIABLES.contains(variable)) {
                errors.add("Disallowed variable: #" + variable);
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
                errors.add("Disallowed method call: " + object + "." + method + "()");
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
        
        
        if (SECURITY_METHODS.contains(object)) {
            return SECURITY_METHODS.contains(method) || SAFE_OBJECT_METHODS.contains(method);
        }

        if (ALLOWED_VARIABLES.contains(object)) {
            return SAFE_OBJECT_METHODS.contains(method);
        }

        return false;
    }

    private List<String> collectWarnings(String expression) {
        List<String> warnings = new ArrayList<>();

        if (expression.contains("#ai.")) {
            warnings.add("Warning: #ai methods may have longer response times due to real-time AI calls (Cold Path)");
        }

        if (expression.length() > 200) {
            warnings.add("Warning: Complex SpEL expression may affect performance");
        }

        long andCount = expression.chars().filter(ch -> ch == '&').count();
        long orCount = expression.chars().filter(ch -> ch == '|').count();
        if (andCount + orCount > 5) {
            warnings.add("Warning: Complex conditions detected. Consider splitting into separate policies");
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

        sb.append("## #ai (Hot Path - Redis LLM Action, <5ms)\n");
        TRUST_METHOD_DOCS.values().stream().sorted().forEach(doc ->
            sb.append("- ").append(doc).append("\n"));

        sb.append("\n## #ai (Cold Path - Real-time AI Analysis, high-risk only)\n");
        AI_METHOD_DOCS.values().stream().sorted().forEach(doc ->
            sb.append("- ").append(doc).append("\n"));

        sb.append("\n## Spring Security Methods\n");
        SECURITY_METHOD_DOCS.values().stream().sorted().forEach(doc ->
            sb.append("- ").append(doc).append("\n"));

        sb.append("\n## Examples\n");
        sb.append("Example 1 (Hot Path recommended):\n");
        sb.append("  #ai.isAllowed() and isAuthenticated()\n");
        sb.append("Example 2 (Hot Path + Spring Security):\n");
        sb.append("  #ai.isAllowed() and hasRole('ROLE_ADMIN')\n");
        sb.append("Example 3 (Cold Path for high-risk):\n");
        sb.append("  #ai.evaluateDataExfiltration() and #ai.isAllowed() and hasAuthority('DATA_ACCESS')\n");

        sb.append("\n## Prohibited\n");
        sb.append("- DO NOT use methods not listed above (e.g. hasPermission, getBean)\n");
        sb.append("- DO NOT use variables other than #ai, #principal, #authentication, #request\n");
        sb.append("- DO NOT use T() type references, new keyword, or reflection\n");
        sb.append("- DO NOT create objects or call Runtime/ProcessBuilder/ScriptEngine\n");

        return sb.toString();
    }
}
