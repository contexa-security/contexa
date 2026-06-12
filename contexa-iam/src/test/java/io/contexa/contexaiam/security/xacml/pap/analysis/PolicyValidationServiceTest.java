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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto.DuplicateType;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto.Severity;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.Mock;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PolicyValidationServiceTest {

    @Mock private PolicyConflictAnalyzer conflictAnalyzer;
    @Mock private PolicyDuplicateDetector duplicateDetector;
    @Mock private PolicyRepository policyRepository;
    @Mock private MessageSource messageSource;

    private PolicyValidationService service;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(any(String.class), any(), any(Locale.class)))
                .thenAnswer(inv -> {
                    String code = inv.getArgument(0);
                    return switch (code) {
                        case "msg.policy.validation.blocked.critical" -> "CRITICAL conflict detected with existing policy";
                        case "msg.policy.validation.blocked.duplicate" -> "Exact duplicate policy already exists";
                        default -> code;
                    };
                });
        service = new PolicyValidationService(conflictAnalyzer, duplicateDetector, policyRepository, messageSource);
    }

    private Policy buildPolicy(Long id, String name) {
        return Policy.builder().id(id).name(name).effect(Policy.Effect.ALLOW).priority(100).isActive(true).build();
    }

    @Nested
    @DisplayName("단일 정책 검증 (validate)")
    class SingleValidation {

        @Test
        @DisplayName("충돌/중복 없으면 canCreate=true")
        void noIssues() {
            when(conflictAnalyzer.analyze(any())).thenReturn(List.of());
            when(duplicateDetector.detect(any(Policy.class))).thenReturn(List.of());

            PolicyValidationReport report = service.validate(buildPolicy(null, "safe"));

            assertThat(report.canCreate()).isTrue();
            assertThat(report.blockedReason()).isNull();
            assertThat(report.conflicts()).isEmpty();
            assertThat(report.duplicates()).isEmpty();
        }

        @Test
        @DisplayName("CRITICAL 충돌 시 canCreate=false")
        void criticalConflictBlocks() {
            when(conflictAnalyzer.analyze(any())).thenReturn(List.of(
                    new PolicyConflictDto(null, "new", 1L, "existing",
                            "Exact conflict", Severity.CRITICAL)));
            when(duplicateDetector.detect(any(Policy.class))).thenReturn(List.of());

            PolicyValidationReport report = service.validate(buildPolicy(null, "blocked"));

            assertThat(report.canCreate()).isFalse();
            assertThat(report.blockedReason()).contains("CRITICAL");
        }

        @Test
        @DisplayName("HIGH 충돌만 있으면 canCreate=true (경고만)")
        void highConflictAllows() {
            when(conflictAnalyzer.analyze(any())).thenReturn(List.of(
                    new PolicyConflictDto(null, "new", 1L, "existing",
                            "Wildcard overlap", Severity.HIGH)));
            when(duplicateDetector.detect(any(Policy.class))).thenReturn(List.of());

            PolicyValidationReport report = service.validate(buildPolicy(null, "warned"));

            assertThat(report.canCreate()).isTrue();
            assertThat(report.hasWarnings()).isTrue();
        }

        @Test
        @DisplayName("EXACT 중복 시 canCreate=false")
        void exactDuplicateBlocks() {
            when(conflictAnalyzer.analyze(any())).thenReturn(List.of());
            when(duplicateDetector.detect(any())).thenReturn(List.of(
                    new DuplicatePolicyDto("Exact duplicate: identical targets, conditions, and effect",
                            List.of(1L), "hash123")));

            PolicyValidationReport report = service.validate(buildPolicy(null, "dup"));

            assertThat(report.canCreate()).isFalse();
            assertThat(report.blockedReason()).contains("Exact duplicate");
        }

        @Test
        @DisplayName("SEMANTIC 중복은 canCreate=true (경고만)")
        void semanticDuplicateAllows() {
            when(conflictAnalyzer.analyze(any())).thenReturn(List.of());
            when(duplicateDetector.detect(any())).thenReturn(List.of(
                    new DuplicatePolicyDto("Semantic duplicate: equivalent after SpEL normalization",
                            List.of(1L), "hash456", DuplicateType.SEMANTIC)));

            PolicyValidationReport report = service.validate(buildPolicy(null, "semantic-dup"));

            assertThat(report.canCreate()).isTrue();
            assertThat(report.hasWarnings()).isTrue();
        }
    }

    @Nested
    @DisplayName("전체 정책 검증 (validateAll)")
    class FullValidation {

        @Test
        @DisplayName("정책 없으면 HEALTHY")
        void emptyPolicies() {
            when(policyRepository.findAllWithDetails()).thenReturn(List.of());

            FullValidationReport report = service.validateAll();

            assertThat(report.totalPolicies()).isEqualTo(0);
            assertThat(report.healthStatus()).isEqualTo("HEALTHY");
        }

        @Test
        @DisplayName("충돌 없으면 HEALTHY")
        void noConflicts() {
            Policy p = buildPolicy(1L, "safe");
            when(policyRepository.findAllWithDetails()).thenReturn(List.of(p));
            when(conflictAnalyzer.analyze(any(), any())).thenReturn(List.of());
            when(duplicateDetector.detect(any(), any())).thenReturn(List.of());

            FullValidationReport report = service.validateAll();

            assertThat(report.healthStatus()).isEqualTo("HEALTHY");
        }

        @Test
        @DisplayName("CRITICAL 충돌 존재 시 CRITICAL")
        void criticalHealth() {
            Policy p = buildPolicy(1L, "conflict");
            when(policyRepository.findAllWithDetails()).thenReturn(List.of(p));
            when(conflictAnalyzer.analyze(any(), any())).thenReturn(List.of(
                    new PolicyConflictDto(1L, "conflict", 2L, "other",
                            "Exact match", Severity.CRITICAL)));
            when(duplicateDetector.detect(any(), any())).thenReturn(List.of());

            FullValidationReport report = service.validateAll();

            assertThat(report.healthStatus()).isEqualTo("CRITICAL");
        }

        @Test
        @DisplayName("HIGH 충돌만 존재 시 WARNING")
        void warningHealth() {
            Policy p = buildPolicy(1L, "warn");
            when(policyRepository.findAllWithDetails()).thenReturn(List.of(p));
            when(conflictAnalyzer.analyze(any(), any())).thenReturn(List.of(
                    new PolicyConflictDto(1L, "warn", 2L, "other",
                            "Wildcard", Severity.HIGH)));
            when(duplicateDetector.detect(any(), any())).thenReturn(List.of());

            FullValidationReport report = service.validateAll();

            assertThat(report.healthStatus()).isEqualTo("WARNING");
        }

        @Test
        @DisplayName("대칭 충돌은 중복 제거됨 (A vs B == B vs A)")
        void deduplicateSymmetricConflicts() {
            Policy p1 = buildPolicy(1L, "p1");
            Policy p2 = buildPolicy(2L, "p2");
            when(policyRepository.findAllWithDetails()).thenReturn(List.of(p1, p2));

            // p1 분석 시 p2와 충돌, p2 분석 시 p1과 충돌 (대칭)
            when(conflictAnalyzer.analyze(eq(p1), any())).thenReturn(List.of(
                    new PolicyConflictDto(1L, "p1", 2L, "p2", "conflict", Severity.HIGH)));
            when(conflictAnalyzer.analyze(eq(p2), any())).thenReturn(List.of(
                    new PolicyConflictDto(2L, "p2", 1L, "p1", "conflict", Severity.HIGH)));
            when(duplicateDetector.detect(any(), any())).thenReturn(List.of());

            FullValidationReport report = service.validateAll();

            assertThat(report.conflicts()).hasSize(1);
        }

        @Test
        @DisplayName("비활성 정책은 검증에서 제외됨")
        void skipInactive() {
            Policy inactive = buildPolicy(1L, "inactive");
            inactive.setIsActive(false);
            when(policyRepository.findAllWithDetails()).thenReturn(List.of(inactive));

            FullValidationReport report = service.validateAll();

            assertThat(report.conflicts()).isEmpty();
        }
    }
}
