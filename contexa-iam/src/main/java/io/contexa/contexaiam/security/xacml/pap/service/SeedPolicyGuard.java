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
package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import org.springframework.expression.spel.SpelNode;
import org.springframework.expression.spel.ast.MethodReference;
import org.springframework.expression.spel.ast.OpAnd;
import org.springframework.expression.spel.ast.StringLiteral;
import org.springframework.expression.spel.standard.SpelExpression;
import org.springframework.expression.spel.standard.SpelExpressionParser;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Keeps the two seed policies that guard the console (D46). Policy 1 opens the sign-in page
 * {@code /contexa/admin/login}; policy 2 keeps the rest of {@code /contexa/admin/**} to administrators. Neither is deleted
 * or disabled: without policy 1 nobody can sign in, and without policy 2 the admin area falls to the decision for a URL
 * no policy covers, which lets anyone in. An edit of either is refused when it would widen what the policy lets through:
 * policy 1 stays an ALLOW policy on the sign-in page only, and policy 2 stays an ALLOW policy on {@code /contexa/admin/**}
 * whose every condition requires {@code hasRole('ADMIN')}, alone or joined with {@code and}.
 */
public final class SeedPolicyGuard {

    public static final long LOGIN_POLICY_ID = 1L;
    public static final long ADMIN_AREA_POLICY_ID = 2L;

    static final String LOGIN_PATH = "/contexa/admin/login";
    static final String ADMIN_AREA_PATH = "/contexa/admin/**";

    static final String REMOVAL_REFUSED = "msg.policy.seed.removal.refused";
    static final String LOGIN_CHANGE_REFUSED = "msg.policy.seed.login.change.refused";
    static final String ADMIN_CHANGE_REFUSED = "msg.policy.seed.admin.change.refused";

    private static final SpelExpressionParser PARSER = new SpelExpressionParser();
    private static final Set<String> ANY_METHOD = Set.of("ANY", "ALL");

    private SeedPolicyGuard() {
    }

    public static boolean isSeedPolicy(Long policyId) {
        return policyId != null && (policyId == LOGIN_POLICY_ID || policyId == ADMIN_AREA_POLICY_ID);
    }

    /** The message key of the refusal to delete or disable the policy, or empty when it is not a seed policy. */
    public static Optional<String> refuseRemoval(Long policyId) {
        return isSeedPolicy(policyId) ? Optional.of(REMOVAL_REFUSED) : Optional.empty();
    }

    /** The message key of the refusal of the edit a policy form asks for, or empty when it is allowed. */
    public static Optional<String> refuseChange(Long policyId, PolicyDto dto) {
        if (!isSeedPolicy(policyId)) {
            return Optional.empty();
        }
        List<Target> targets = new ArrayList<>();
        if (dto.getTargets() != null) {
            dto.getTargets().stream().filter(Objects::nonNull).forEach(target -> targets.add(
                    new Target(target.getTargetType(), target.getTargetIdentifier(), target.getHttpMethod())));
        }
        List<String> conditions = new ArrayList<>();
        if (dto.getRules() != null) {
            for (RuleDto rule : dto.getRules()) {
                if (rule != null && rule.getConditions() != null) {
                    rule.getConditions().stream().filter(Objects::nonNull)
                            .map(ConditionDto::getExpression).forEach(conditions::add);
                }
            }
        }
        return refuseChange(policyId, dto.getEffect(), targets, conditions);
    }

    /** The message key of the refusal of a policy as it is about to be saved, or empty when it is allowed. */
    public static Optional<String> refuseChange(Policy policy) {
        if (policy == null || !isSeedPolicy(policy.getId())) {
            return Optional.empty();
        }
        List<Target> targets = policy.getTargets().stream()
                .map(SeedPolicyGuard::target)
                .toList();
        List<String> conditions = policy.getRules().stream()
                .flatMap(rule -> rule.getConditions().stream())
                .map(PolicyCondition::getExpression)
                .toList();
        return refuseChange(policy.getId(), policy.getEffect(), targets, conditions);
    }

    private static Optional<String> refuseChange(Long policyId, Policy.Effect effect, List<Target> targets,
                                                 Collection<String> conditions) {
        if (policyId == LOGIN_POLICY_ID) {
            boolean onlyTheSignInPage = !targets.isEmpty()
                    && targets.stream().allMatch(target -> target.isUrl(LOGIN_PATH));
            return effect == Policy.Effect.ALLOW && onlyTheSignInPage
                    ? Optional.empty() : Optional.of(LOGIN_CHANGE_REFUSED);
        }
        boolean coversTheAdminArea = targets.stream()
                .anyMatch(target -> target.isUrl(ADMIN_AREA_PATH) && target.anyMethod());
        boolean administratorsOnly = !conditions.isEmpty()
                && conditions.stream().allMatch(SeedPolicyGuard::requiresAdministrator);
        return effect == Policy.Effect.ALLOW && coversTheAdminArea && administratorsOnly
                ? Optional.empty() : Optional.of(ADMIN_CHANGE_REFUSED);
    }

    /**
     * Whether a condition lets through no one but an administrator: it is {@code hasRole('ADMIN')} (or the same role
     * named with its prefix), or a conjunction one side of which is such a condition. Conditions of a policy are joined
     * with {@code or}, so the policy is no wider than {@code hasRole('ADMIN')} only when every condition is.
     */
    static boolean requiresAdministrator(String expression) {
        if (expression == null || expression.isBlank()) {
            return false;
        }
        try {
            return requiresAdministrator(((SpelExpression) PARSER.parseExpression(expression)).getAST());
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean requiresAdministrator(SpelNode node) {
        if (node instanceof OpAnd) {
            return requiresAdministrator(node.getChild(0)) || requiresAdministrator(node.getChild(1));
        }
        if (node instanceof MethodReference method && node.getChildCount() == 1
                && node.getChild(0) instanceof StringLiteral literal) {
            String argument = String.valueOf(literal.getLiteralValue().getValue());
            return switch (method.getName()) {
                case "hasRole" -> "ADMIN".equals(argument) || "ROLE_ADMIN".equals(argument);
                case "hasAuthority" -> "ROLE_ADMIN".equals(argument);
                default -> false;
            };
        }
        return false;
    }

    private static Target target(PolicyTarget target) {
        return new Target(target.getTargetType(), target.getTargetIdentifier(), target.getHttpMethod());
    }

    private record Target(String type, String identifier, String httpMethod) {

        boolean isUrl(String path) {
            return "URL".equals(type) && path.equals(identifier != null ? identifier.trim() : null);
        }

        boolean anyMethod() {
            return httpMethod == null || httpMethod.isBlank() || ANY_METHOD.contains(httpMethod.trim());
        }
    }
}
