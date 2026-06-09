package io.contexa.contexaiam.security.xacml.pdp.translator;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Converts policy conditions to valid SpEL expressions.
 * Handles plain authority names, mixed expressions, and permission stripping for URL policies.
 */
public class PolicyExpressionConverter {

    private static final Pattern AUTHORITY_PATTERN = Pattern.compile("^[A-Z_]+$");
    private static final Pattern HAS_PERMISSION_PATTERN =
            Pattern.compile("\\s*(?:and\\s+)?hasPermission\\([^)]*\\)(?:\\s*and)?\\s*");

    /**
     * Converts a Policy entity's conditions into a single SpEL expression string.
     */
    public String toExpression(Policy policy) {
        List<String> conditionExpressions = policy.getRules().stream()
                .flatMap(rule -> rule.getConditions().stream())
                .map(PolicyCondition::getExpression)
                .map(PolicyExpressionConverter::normalize)
                .toList();

        if (conditionExpressions.isEmpty()) {
            return (policy.getEffect() == Policy.Effect.ALLOW) ? "permitAll" : "denyAll";
        }

        String finalExpression;

        if (conditionExpressions.size() == 1) {
            finalExpression = conditionExpressions.get(0);
        } else {
            boolean allAreSimpleAuthorities = conditionExpressions.stream()
                    .allMatch(expr -> AUTHORITY_PATTERN.matcher(expr).matches());

            if (allAreSimpleAuthorities) {
                finalExpression = "hasAnyAuthority(" +
                        conditionExpressions.stream().map(auth -> "'" + auth + "'")
                                .collect(Collectors.joining(",")) + ")";
            } else {
                finalExpression = conditionExpressions.stream()
                        .map(expr -> "(" + expr + ")")
                        .collect(Collectors.joining(" or "));
            }
        }

        if (policy.getEffect() == Policy.Effect.DENY) {
            finalExpression = "!(" + finalExpression + ")";
        }
        return stripHasPermission(finalExpression);
    }

    /**
     * Normalizes a condition expression to valid SpEL.
     * Plain authority names like "ROLE_ADMIN" are wrapped in hasAuthority().
     * Mixed expressions like "ROLE_ADMIN or hasRole('MANAGER')" are parsed token by token.
     */
    public static String normalize(String expression) {
        if (expression == null || expression.isBlank()) return "permitAll";
        String trimmed = expression.trim();

        if ("permitAll".equals(trimmed) || "denyAll".equals(trimmed)
                || "isAuthenticated()".equals(trimmed)) {
            return trimmed;
        }

        if (AUTHORITY_PATTERN.matcher(trimmed).matches()) {
            return "hasAuthority('" + trimmed + "')";
        }

        if (trimmed.contains(" or ") || trimmed.contains(" and ")) {
            String[] orParts = trimmed.split("\\s+or\\s+");
            List<String> normalized = new ArrayList<>();
            for (String orPart : orParts) {
                String[] andParts = orPart.trim().split("\\s+and\\s+");
                List<String> normalizedAnd = new ArrayList<>();
                for (String part : andParts) {
                    String p = part.trim();
                    if (p.startsWith("(") && p.endsWith(")")) {
                        p = p.substring(1, p.length() - 1).trim();
                    }
                    if (AUTHORITY_PATTERN.matcher(p).matches()) {
                        normalizedAnd.add("hasAuthority('" + p + "')");
                    } else {
                        normalizedAnd.add(p);
                    }
                }
                normalized.add(String.join(" and ", normalizedAnd));
            }
            return normalized.stream().map(s -> "(" + s + ")").collect(Collectors.joining(" or "));
        }

        return trimmed;
    }

    /**
     * Strips hasPermission() calls from URL-type policy expressions.
     */
    public static String stripHasPermission(String expression) {
        String cleaned = HAS_PERMISSION_PATTERN.matcher(expression).replaceAll(" ");
        cleaned = cleaned.replaceAll("\\s+and\\s+and\\s+", " and ");
        cleaned = cleaned.replaceAll("^\\s*and\\s+", "");
        cleaned = cleaned.replaceAll("\\s+and\\s*$", "");
        cleaned = cleaned.trim();
        return cleaned.isEmpty() ? "denyAll" : cleaned;
    }
}
