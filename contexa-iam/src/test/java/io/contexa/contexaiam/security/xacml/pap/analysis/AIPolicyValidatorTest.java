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

import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport.CheckResult;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AIPolicyValidatorTest {

    @Mock private RoleRepository roleRepository;
    @Mock private PermissionRepository permissionRepository;
    @Mock private PolicyConflictAnalyzer conflictAnalyzer;
    @Mock private PolicyDuplicateDetector duplicateDetector;
    @Mock private MessageSource messageSource;

    private AIPolicyValidator validator;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(any(String.class), any(), any(java.util.Locale.class))).thenAnswer(inv -> inv.getArgument(0));
        validator = new AIPolicyValidator(roleRepository, permissionRepository,
                conflictAnalyzer, duplicateDetector, messageSource);
        when(conflictAnalyzer.analyze(any())).thenReturn(List.of());
        when(duplicateDetector.detect(any())).thenReturn(List.of());
    }

    private Policy buildPolicy(String condition) {
        Policy policy = Policy.builder().name("ai-test").effect(Policy.Effect.ALLOW)
                .priority(100).source(Policy.PolicySource.AI_GENERATED).build();
        PolicyTarget target = PolicyTarget.builder().policy(policy)
                .targetType("URL").targetIdentifier("/api/test").build();
        policy.getTargets().add(target);
        PolicyRule rule = PolicyRule.builder().policy(policy).build();
        PolicyCondition cond = PolicyCondition.builder().rule(rule).expression(condition).build();
        rule.setConditions(Set.of(cond));
        policy.getRules().add(rule);
        return policy;
    }

    // ── 1. 참조 무결성 ──────────────────────────────────────────

    @Nested
    @DisplayName("참조 무결성 검증")
    class ReferentialIntegrity {

        @Test
        @DisplayName("참조된 역할이 모두 존재하면 PASS")
        void allRolesExist() {
            when(roleRepository.findByRoleName("ROLE_ADMIN")).thenReturn(Optional.of(new Role()));
            Policy policy = buildPolicy("hasAuthority('ROLE_ADMIN')");

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.items().stream()
                    .filter(i -> "Referential Integrity".equals(i.checkName()))
                    .findFirst().get().result()).isEqualTo(CheckResult.PASS);
        }

        @Test
        @DisplayName("존재하지 않는 역할 참조 시 FAIL")
        void missingRole() {
            when(roleRepository.findByRoleName("ROLE_NONEXISTENT")).thenReturn(Optional.empty());
            Policy policy = buildPolicy("hasAuthority('ROLE_NONEXISTENT')");

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.items().stream()
                    .filter(i -> "Referential Integrity".equals(i.checkName()))
                    .findFirst().get().result()).isEqualTo(CheckResult.FAIL);
            assertThat(report.canApprove()).isFalse();
        }

        @Test
        @DisplayName("존재하지 않는 권한 참조 시 FAIL")
        void missingPermission() {
            when(permissionRepository.findByName("PERM_MISSING")).thenReturn(Optional.empty());
            Policy policy = buildPolicy("hasAuthority('PERM_MISSING')");

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.canApprove()).isFalse();
        }
    }

    // ── 2. 충돌 검사 ────────────────────────────────────────────

    @Nested
    @DisplayName("충돌 검사")
    class ConflictCheck {

        @Test
        @DisplayName("충돌 없으면 PASS")
        void noConflicts() {
            Policy policy = buildPolicy("hasAuthority('ROLE_USER')");
            when(roleRepository.findByRoleName("ROLE_USER")).thenReturn(Optional.of(new Role()));

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.items().stream()
                    .filter(i -> "Conflict Check".equals(i.checkName()))
                    .findFirst().get().result()).isEqualTo(CheckResult.PASS);
        }

        @Test
        @DisplayName("CRITICAL 충돌 시 FAIL")
        void criticalConflict() {
            when(conflictAnalyzer.analyze(any())).thenReturn(List.of(
                    new PolicyConflictDto(null, "ai", 1L, "existing", "conflict",
                            PolicyConflictDto.Severity.CRITICAL)));
            when(roleRepository.findByRoleName("ROLE_USER")).thenReturn(Optional.of(new Role()));
            Policy policy = buildPolicy("hasAuthority('ROLE_USER')");

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.canApprove()).isFalse();
        }

        @Test
        @DisplayName("HIGH 충돌만 있으면 WARNING")
        void highConflictWarning() {
            when(conflictAnalyzer.analyze(any())).thenReturn(List.of(
                    new PolicyConflictDto(null, "ai", 1L, "existing", "overlap",
                            PolicyConflictDto.Severity.HIGH)));
            when(roleRepository.findByRoleName("ROLE_USER")).thenReturn(Optional.of(new Role()));
            Policy policy = buildPolicy("hasAuthority('ROLE_USER')");

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.canApprove()).isTrue();
            assertThat(report.hasWarnings()).isTrue();
        }
    }

    // ── 3. 중복 검사 ────────────────────────────────────────────

    @Nested
    @DisplayName("중복 검사")
    class DuplicateCheck {

        @Test
        @DisplayName("EXACT 중복 시 FAIL")
        void exactDuplicate() {
            when(duplicateDetector.detect(any())).thenReturn(List.of(
                    new DuplicatePolicyDto("exact", List.of(1L), "hash",
                            DuplicatePolicyDto.DuplicateType.EXACT)));
            when(roleRepository.findByRoleName("ROLE_USER")).thenReturn(Optional.of(new Role()));
            Policy policy = buildPolicy("hasAuthority('ROLE_USER')");

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.canApprove()).isFalse();
        }

        @Test
        @DisplayName("SEMANTIC 중복만 있으면 WARNING")
        void semanticDuplicateWarning() {
            when(duplicateDetector.detect(any())).thenReturn(List.of(
                    new DuplicatePolicyDto("semantic", List.of(1L), "hash",
                            DuplicatePolicyDto.DuplicateType.SEMANTIC)));
            when(roleRepository.findByRoleName("ROLE_USER")).thenReturn(Optional.of(new Role()));
            Policy policy = buildPolicy("hasAuthority('ROLE_USER')");

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.canApprove()).isTrue();
            assertThat(report.hasWarnings()).isTrue();
        }
    }

    // ── 4. 위험 패턴 ────────────────────────────────────────────

    @Nested
    @DisplayName("위험 패턴 검사")
    class DangerousPatterns {

        @Test
        @DisplayName("permitAll + ALLOW effect -> WARNING")
        void permitAllWarning() {
            Policy policy = buildPolicy("permitAll");

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.items().stream()
                    .filter(i -> "Dangerous Patterns".equals(i.checkName()))
                    .findFirst().get().result()).isEqualTo(CheckResult.WARNING);
        }

        @Test
        @DisplayName("isAuthenticated() 단독 사용 -> WARNING")
        void isAuthenticatedAloneWarning() {
            Policy policy = buildPolicy("isAuthenticated()");

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.items().stream()
                    .filter(i -> "Dangerous Patterns".equals(i.checkName()))
                    .findFirst().get().result()).isEqualTo(CheckResult.WARNING);
        }

        @Test
        @DisplayName("정상 조건은 PASS")
        void normalConditionPass() {
            when(roleRepository.findByRoleName("ROLE_ADMIN")).thenReturn(Optional.of(new Role()));
            Policy policy = buildPolicy("hasAuthority('ROLE_ADMIN')");

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.items().stream()
                    .filter(i -> "Dangerous Patterns".equals(i.checkName()))
                    .findFirst().get().result()).isEqualTo(CheckResult.PASS);
        }
    }

    // ── 5. 전체 통과 ────────────────────────────────────────────

    @Nested
    @DisplayName("전체 검증 통과")
    class AllPass {

        @Test
        @DisplayName("모든 검증 항목 PASS이면 canApprove=true")
        void allPassCanApprove() {
            when(roleRepository.findByRoleName("ROLE_USER")).thenReturn(Optional.of(new Role()));
            Policy policy = buildPolicy("hasAuthority('ROLE_USER')");

            AIPolicyValidationReport report = validator.validate(policy);

            assertThat(report.canApprove()).isTrue();
            assertThat(report.blockedReason()).isNull();
            assertThat(report.items()).hasSize(5);
            assertThat(report.items()).allMatch(i -> i.result() != CheckResult.FAIL);
        }
    }
}
