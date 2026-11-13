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
package io.contexa.contexaiam.security.xacml.pap.analysis;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.testsupport.I18nTestSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * D65: the dashboard compared every policy with every other one, rebuilding the signatures and target keys of each pair:
 * two thousand policies took eleven seconds. The full validation now reads each policy once and compares only the
 * policies that can conflict or be duplicates. Its result is checked against the comparison of every pair, on a
 * generated set that has exact, semantic, subset and role hierarchy duplicates and exact, wildcard, shared-prefix and
 * method conflicts, and its time on the shape of the review's two thousand policies is bounded.
 */
@ExtendWith(I18nTestSupport.EnglishLocale.class)
class PolicyValidationAtScaleTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyValidationAtScaleTest.class);

    private static final String[] PATHS = {
            "/api/v%d/orders", "/api/v%d/orders/**", "/api/*/orders", "/api/{tenant}/orders/%d", "/api/v%d/items?",
            "/contexa/admin/bigx%d/**", "/contexa/admin/**", "/static/**", "/**", "/reports/%d", "/reports/%d/**",
            "//double/%d/*", "relative/%d/**", "/api/v%d/a{b/c"
    };
    private static final String[] METHODS = {null, "ANY", "ALL", "GET", "POST", "get"};
    private static final String[] CONDITIONS = {
            "hasRole('ADMIN')", "hasAuthority('ROLE_ADMIN')", "hasRole('USER')", "hasRole('MANAGER')",
            "isAuthenticated()", "hasRole('USER') and isFullyAuthenticated()", "hasAuthority('READ')", " hasRole('USER') "
    };

    private final MessageSource messages = I18nTestSupport.englishMessageSource();
    private final PolicyRepository repository = mock(PolicyRepository.class);
    private final RoleHierarchyImpl hierarchy =
            RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_MANAGER\nROLE_MANAGER > ROLE_USER");
    private final PolicyConflictAnalyzer conflicts = new PolicyConflictAnalyzer(repository, messages);
    private final PolicyDuplicateDetector duplicates = new PolicyDuplicateDetector(repository, hierarchy, messages);

    @Test
    @DisplayName("the conflicts and duplicates of all policies are those of comparing every pair, in the same order")
    void theResultIsTheOneOfComparingEveryPair() {
        List<Policy> policies = generated(2500, 7L);

        List<PolicyConflictDto> everyPairConflicts = new ArrayList<>();
        List<DuplicatePolicyDto> everyPairDuplicates = new ArrayList<>();
        for (Policy policy : policies) {
            if (policy.getIsActive()) {
                everyPairConflicts.addAll(conflicts.analyze(policy, policies));
                everyPairDuplicates.addAll(duplicates.detect(policy, policies));
            }
        }
        List<PolicyConflictDto> allConflicts = conflicts.analyzeAll(policies);
        List<DuplicatePolicyDto> allDuplicates = duplicates.detectAll(policies);

        assertThat(allConflicts).isEqualTo(everyPairConflicts);
        assertThat(allDuplicates).isEqualTo(everyPairDuplicates);
        // The set covers every kind of finding, so the equality above says something about each of them.
        assertThat(everyPairConflicts.stream().map(PolicyConflictDto::severity).collect(Collectors.toSet()))
                .contains(PolicyConflictDto.Severity.CRITICAL, PolicyConflictDto.Severity.HIGH,
                        PolicyConflictDto.Severity.MEDIUM);
        assertThat(everyPairDuplicates.stream().map(DuplicatePolicyDto::type).collect(Collectors.toSet()))
                .containsExactlyInAnyOrder(DuplicatePolicyDto.DuplicateType.values());
    }

    @Test
    @DisplayName("the review's two thousand policies are validated well within the five seconds of the dashboard")
    void twoThousandPoliciesAreValidatedQuickly() {
        List<Policy> policies = new ArrayList<>(seedPolicies());
        for (int index = 1; index <= 2000; index++) {
            policies.add(policy(100L + index, "iamt-big-policy-" + index, Policy.Effect.ALLOW, true,
                    Map.of("/contexa/admin/bigx" + index + "/**", "ANY"), "isAuthenticated()"));
        }
        when(repository.findAllWithDetails()).thenReturn(policies);
        PolicyValidationService service = new PolicyValidationService(conflicts, duplicates, repository, messages);
        service.validateAll();

        long startedAt = System.nanoTime();
        FullValidationReport report = service.validateAll();
        long millis = (System.nanoTime() - startedAt) / 1_000_000;

        log.info("D65 full validation of {} policies took {} ms", policies.size(), millis);
        assertThat(report.totalPolicies()).isEqualTo(2004);
        assertThat(millis).isLessThan(1500);
    }

    private static List<Policy> seedPolicies() {
        return List.of(
                policy(1L, "ALLOW_CONTEXA_ADMIN_LOGIN", Policy.Effect.ALLOW, true,
                        Map.of("/contexa/admin/login", "ANY"), "permitAll"),
                policy(2L, "ALLOW_CONTEXA_ADMIN_ADMINISTRATORS", Policy.Effect.ALLOW, true,
                        Map.of("/contexa/admin/**", "ANY"), "hasRole('ADMIN')"),
                policy(3L, "ALLOW_CONTEXA_ZERO_TRUST_SELF_SERVICE", Policy.Effect.ALLOW, true,
                        Map.of("/contexa/admin/api/aiam/zero-trust/**", "ANY",
                                "/contexa/admin/api/aiam/sse/zero-trust/**", "ANY"), "isAuthenticated()"),
                policy(4L, "DENY_BLOCKED", Policy.Effect.DENY, true,
                        Map.of("/contexa/admin/blogs/**", "POST"), "hasAuthority('ROLE_BLOCKED')"));
    }

    private static List<Policy> generated(int count, long seed) {
        Random random = new Random(seed);
        List<Policy> policies = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            Policy.Effect effect = random.nextInt(10) < 7 ? Policy.Effect.ALLOW : Policy.Effect.DENY;
            Policy policy = Policy.builder().id((long) index + 1).name("generated-" + index).effect(effect)
                    .priority(random.nextInt(500)).isActive(random.nextInt(20) != 0).build();
            int targetCount = 1 + random.nextInt(3);
            for (int target = 0; target < targetCount; target++) {
                if (random.nextInt(8) == 0) {
                    policy.addTarget(PolicyTarget.builder().targetType("METHOD")
                            .targetIdentifier("io.contexa.Service.method" + random.nextInt(40))
                            .httpMethod(null).build());
                    continue;
                }
                String path = String.format(PATHS[random.nextInt(PATHS.length)], random.nextInt(30));
                policy.addTarget(PolicyTarget.builder().targetType("URL").targetIdentifier(path)
                        .httpMethod(METHODS[random.nextInt(METHODS.length)]).build());
            }
            PolicyRule rule = PolicyRule.builder().build();
            int conditionCount = 1 + random.nextInt(2);
            for (int condition = 0; condition < conditionCount; condition++) {
                rule.addCondition(PolicyCondition.builder()
                        .expression(CONDITIONS[random.nextInt(CONDITIONS.length)]).build());
            }
            policy.addRule(rule);
            policies.add(policy);
        }
        return policies;
    }

    private static Policy policy(long id, String name, Policy.Effect effect, boolean active, Map<String, String> targets,
                                 String condition) {
        Policy policy = Policy.builder().id(id).name(name).effect(effect).priority(100).isActive(active).build();
        targets.forEach((path, method) -> policy.addTarget(
                PolicyTarget.builder().targetType("URL").targetIdentifier(path).httpMethod(method).build()));
        PolicyRule rule = PolicyRule.builder().build();
        rule.addCondition(PolicyCondition.builder().expression(condition).build());
        policy.addRule(rule);
        return policy;
    }
}
