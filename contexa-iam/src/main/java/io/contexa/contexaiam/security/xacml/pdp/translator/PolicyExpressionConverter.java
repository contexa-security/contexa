/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.security.xacml.pdp.translator;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.PolicyExpressionValidator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.SpelLiteral;

import java.util.List;
import java.util.Set;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Converts policy conditions to valid SpEL expressions.
 * Handles plain authority names, mixed expressions, and permission stripping for URL policies.
 *
 * <p>The produced expression is the policy condition. Its meaning depends on the policy effect:
 * for an ALLOW policy a satisfied condition is Permit and an unsatisfied one is Deny; for a DENY
 * policy a satisfied condition is Deny and an unsatisfied one is NotApplicable. A policy without
 * conditions always applies, so its condition is {@code permitAll} for both effects.</p>
 */
public class PolicyExpressionConverter {

    private static final Pattern AUTHORITY_PATTERN = Pattern.compile("^[A-Z_]+$");
    /** SpEL operator keywords written in upper case, which are no authority names. */
    private static final Set<String> SPEL_KEYWORDS = Set.of("AND", "OR", "NOT", "TRUE", "FALSE", "NULL",
            "INSTANCEOF", "MATCHES", "BETWEEN", "LT", "GT", "LE", "GE", "EQ", "NE", "DIV", "MOD", "T");
    private static final Pattern HAS_PERMISSION_PATTERN =
            Pattern.compile("\\s*(?:and\\s+)?hasPermission\\([^)]*\\)(?:\\s*and)?\\s*");

    /**
     * Converts a Policy entity's conditions into a single SpEL condition expression string.
     * The expression is never negated for DENY policies; the caller applies the effect.
     */
    public String toExpression(Policy policy) {
        List<String> conditionExpressions = policy.getRules().stream()
                .flatMap(rule -> rule.getConditions().stream())
                .map(PolicyCondition::getExpression)
                .map(PolicyExpressionConverter::normalize)
                .toList();

        if (conditionExpressions.isEmpty()) {
            return "permitAll";
        }

        String finalExpression;

        if (conditionExpressions.size() == 1) {
            finalExpression = conditionExpressions.get(0);
        } else {
            boolean allAreSimpleAuthorities = conditionExpressions.stream()
                    .allMatch(expr -> AUTHORITY_PATTERN.matcher(expr).matches());

            if (allAreSimpleAuthorities) {
                finalExpression = "hasAnyAuthority(" +
                        conditionExpressions.stream().map(SpelLiteral::quote)
                                .collect(Collectors.joining(",")) + ")";
            } else {
                finalExpression = conditionExpressions.stream()
                        .map(expr -> "(" + expr + ")")
                        .collect(Collectors.joining(" or "));
            }
        }

        String stripped = removePermissionChecks(finalExpression);
        if (stripped.isEmpty()) {
            // Object-level permission checks cannot be evaluated for a URL. Fail closed for both
            // effects: an ALLOW policy never permits and a DENY policy always applies.
            return policy.getEffect() == Policy.Effect.DENY ? "permitAll" : "denyAll";
        }
        return stripped;
    }

    /**
     * Returns why the URL condition of a policy must not be compiled, or {@code null} when it is
     * acceptable. Every stored condition and the converted expression are checked, so a forbidden
     * construct is rejected even when the conversion would have removed it.
     *
     * @param policy     the policy whose stored conditions are checked
     * @param expression the expression produced by {@link #toExpression(Policy)} for the policy
     */
    public String findLoadViolation(Policy policy, String expression) {
        for (PolicyRule rule : policy.getRules()) {
            for (PolicyCondition condition : rule.getConditions()) {
                String rawExpression = condition.getExpression();
                if (rawExpression == null || rawExpression.isBlank()) {
                    continue;
                }
                Optional<String> violation = PolicyExpressionValidator.findViolation(rawExpression);
                if (violation.isPresent()) {
                    return violation.get();
                }
            }
        }
        return PolicyExpressionValidator.findViolation(expression).orElse(null);
    }

    /**
     * Normalizes a condition expression to valid SpEL. Plain authority names like "ROLE_ADMIN" are wrapped in
     * hasAuthority(); in a mixed expression like "ROLE_ADMIN or hasRole('MANAGER')" only those names are wrapped and
     * the expression keeps its structure, so grouping and operator precedence mean what the author wrote (CF-08).
     */
    public static String normalize(String expression) {
        if (expression == null || expression.isBlank()) return "permitAll";
        String trimmed = expression.trim();

        if ("permitAll".equals(trimmed) || "denyAll".equals(trimmed)
                || "isAuthenticated()".equals(trimmed)) {
            return trimmed;
        }

        if (AUTHORITY_PATTERN.matcher(trimmed).matches()) {
            return SpelLiteral.hasAuthority(trimmed);
        }

        return wrapBareAuthorities(trimmed);
    }

    /**
     * Wraps each bare authority name in hasAuthority(): an upper-case word outside quotes that is neither a SpEL
     * keyword, nor a call, nor a property or a type member. Everything else is copied as it is.
     */
    private static String wrapBareAuthorities(String expression) {
        StringBuilder normalized = new StringBuilder(expression.length() + 16);
        int length = expression.length();
        int index = 0;
        while (index < length) {
            char current = expression.charAt(index);
            if (current == '\'' || current == '"') {
                int end = endOfQuoted(expression, index);
                normalized.append(expression, index, end);
                index = end;
            } else if (Character.isJavaIdentifierStart(current)) {
                int end = index;
                while (end < length && Character.isJavaIdentifierPart(expression.charAt(end))) {
                    end++;
                }
                String word = expression.substring(index, end);
                if (isBareAuthority(expression, index, end, word)) {
                    normalized.append(SpelLiteral.hasAuthority(word));
                } else {
                    normalized.append(word);
                }
                index = end;
            } else {
                normalized.append(current);
                index++;
            }
        }
        return normalized.toString();
    }

    /** The index just past a quoted literal starting at {@code start}; a doubled quote is an escaped one. */
    private static int endOfQuoted(String expression, int start) {
        char quote = expression.charAt(start);
        int index = start + 1;
        while (index < expression.length()) {
            if (expression.charAt(index) == quote) {
                if (index + 1 < expression.length() && expression.charAt(index + 1) == quote) {
                    index += 2;
                    continue;
                }
                return index + 1;
            }
            index++;
        }
        return expression.length();
    }

    private static boolean isBareAuthority(String expression, int start, int end, String word) {
        if (!AUTHORITY_PATTERN.matcher(word).matches() || SPEL_KEYWORDS.contains(word)) {
            return false;
        }
        char before = start > 0 ? expression.charAt(start - 1) : ' ';
        if (before == '.' || before == '#' || before == '@' || before == '$') {
            return false;
        }
        int next = end;
        while (next < expression.length() && Character.isWhitespace(expression.charAt(next))) {
            next++;
        }
        char after = next < expression.length() ? expression.charAt(next) : ' ';
        return after != '(' && after != '.' && after != '[';
    }

    /**
     * Strips hasPermission() calls from URL-type policy expressions.
     */
    public static String stripHasPermission(String expression) {
        String cleaned = removePermissionChecks(expression);
        return cleaned.isEmpty() ? "denyAll" : cleaned;
    }

    private static String removePermissionChecks(String expression) {
        String cleaned = HAS_PERMISSION_PATTERN.matcher(expression).replaceAll(" ");
        cleaned = cleaned.replaceAll("\\s+and\\s+and\\s+", " and ");
        cleaned = cleaned.replaceAll("^\\s*and\\s+", "");
        cleaned = cleaned.replaceAll("\\s+and\\s*$", "");
        return cleaned.trim();
    }
}
