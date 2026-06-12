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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.domain.entity.policy.PolicyVersion;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.analysis.AIPolicyValidator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictException;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyImpactAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicySimulator;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto.Severity;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.Mock;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultPolicyServiceConflictTest {

    @Mock private PolicyRepository policyRepository;
    @Mock private PolicyRetrievalPoint policyRetrievalPoint;
    @Mock private CustomDynamicAuthorizationManager authorizationManager;
    @Mock private PolicyEnrichmentService policyEnrichmentService;
    @Mock private IntegrationEventBus eventBus;
    @Mock private PermissionRepository permissionRepository;
    @Mock private ManagedResourceRepository managedResourceRepository;
    @Mock private CentralAuditFacade centralAuditFacade;
    @Mock private PolicyConflictAnalyzer policyConflictAnalyzer;
    @Mock private PolicyValidationService policyValidationService;
    @Mock private PolicyVersionService policyVersionService;
    @Mock private PolicyImpactAnalyzer policyImpactAnalyzer;
    @Mock private PolicySimulator policySimulator;
    @Mock private MessageSource messageSource;
    @Mock private AIPolicyValidator aiPolicyValidator;
    @Mock private PolicyReloadBroadcaster policyReloadBroadcaster;

    private DefaultPolicyService service;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(any(String.class), any(), any(Locale.class))).thenAnswer(inv -> inv.getArgument(0));
        service = new DefaultPolicyService(
                policyRepository, policyRetrievalPoint, authorizationManager,
                policyEnrichmentService, eventBus, permissionRepository,
                managedResourceRepository, centralAuditFacade, policyConflictAnalyzer,
                policyValidationService, policyVersionService, policyImpactAnalyzer,
                policySimulator, messageSource, aiPolicyValidator);
        service.setPolicyReloadBroadcaster(policyReloadBroadcaster);
    }

    private PolicyDto buildPolicyDto(String name, Policy.Effect effect) {
        return PolicyDto.builder()
                .name(name).description("test").effect(effect).priority(100)
                .targets(List.of(TargetDto.builder()
                        .targetType("URL").targetIdentifier("/api/test")
                        .httpMethod("GET").build()))
                .rules(List.of(new RuleDto("rule",
                        List.of(new ConditionDto("hasAuthority('ROLE_USER')",
                                PolicyCondition.AuthorizationPhase.PRE_AUTHORIZE)))))
                .build();
    }

    // ── 1. CRITICAL 충돌 시 생성 차단 ───────────────────────────

    @Nested
    @DisplayName("CRITICAL 충돌 시 생성 차단")
    class CriticalConflictBlocking {

        @Test
        @DisplayName("CRITICAL 충돌 시 createPolicy가 PolicyConflictException을 발생시킴")
        void createPolicyBlockedByCriticalConflict() {
            PolicyDto dto = buildPolicyDto("allow-users", Policy.Effect.ALLOW);

            when(policyConflictAnalyzer.analyze(any(Policy.class)))
                    .thenReturn(List.of(new PolicyConflictDto(
                            null, "allow-users", 1L, "deny-users",
                            "ALLOW vs DENY on /api/test", Severity.CRITICAL)));

            assertThatThrownBy(() -> service.createPolicy(dto))
                    .isInstanceOf(PolicyConflictException.class)
                    .hasMessageContaining("msg.policy.validation.conflicts.detected")
                    .satisfies(ex -> {
                        PolicyConflictException pce = (PolicyConflictException) ex;
                        assertThat(pce.getConflicts()).hasSize(1);
                        assertThat(pce.getConflicts().get(0).severity()).isEqualTo(Severity.CRITICAL);
                    });

            verify(policyRepository, never()).save(any());
        }

        @Test
        @DisplayName("CRITICAL 충돌 시 updatePolicy가 PolicyConflictException을 발생시킴")
        void updatePolicyBlockedByCriticalConflict() {
            PolicyDto dto = buildPolicyDto("allow-users", Policy.Effect.ALLOW);
            dto.setId(10L);

            Policy existing = Policy.builder()
                    .id(10L).name("allow-users").effect(Policy.Effect.ALLOW).priority(100).build();
            when(policyRepository.findByIdWithDetails(10L)).thenReturn(Optional.of(existing));

            when(policyConflictAnalyzer.analyze(any(Policy.class)))
                    .thenReturn(List.of(new PolicyConflictDto(
                            10L, "allow-users", 2L, "deny-users",
                            "Conflict on update", Severity.CRITICAL)));

            assertThatThrownBy(() -> service.updatePolicy(dto))
                    .isInstanceOf(PolicyConflictException.class);
        }
    }

    // ── 2. CRITICAL 미만 충돌은 경고만 발생 ─────────────────────

    @Nested
    @DisplayName("HIGH 이상 충돌은 생성 차단")
    class HighConflictBlocking {

        @Test
        @DisplayName("HIGH 충돌은 생성을 차단하고 PolicyConflictException을 발생시킴")
        void highConflictBlocksCreation() {
            PolicyDto dto = buildPolicyDto("allow-path", Policy.Effect.ALLOW);

            when(policyConflictAnalyzer.analyze(any(Policy.class)))
                    .thenReturn(List.of(new PolicyConflictDto(
                            null, "allow-path", 1L, "deny-wildcard",
                            "Wildcard overlap", Severity.HIGH)));

            assertThatThrownBy(() -> service.createPolicy(dto))
                    .isInstanceOf(PolicyConflictException.class);

            verify(policyRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("MEDIUM 이하 충돌은 경고만 발생")
    class MediumConflictWarning {

        @Test
        @DisplayName("MEDIUM 충돌은 생성을 허용함")
        void mediumConflictAllowsCreation() {
            PolicyDto dto = buildPolicyDto("allow-get", Policy.Effect.ALLOW);

            when(policyConflictAnalyzer.analyze(any(Policy.class)))
                    .thenReturn(List.of(new PolicyConflictDto(
                            null, "allow-get", 1L, "deny-any",
                            "Method overlap", Severity.MEDIUM)));
            when(policyRepository.save(any(Policy.class)))
                    .thenAnswer(inv -> {
                        Policy p = inv.getArgument(0);
                        p.setId(100L);
                        return p;
                    });

            Policy result = service.createPolicy(dto);

            assertThat(result).isNotNull();
            verify(policyRepository).save(any(Policy.class));
        }
    }

    // ── 3. 충돌 없을 때 정상 흐름 ───────────────────────────────

    @Nested
    @DisplayName("충돌 없을 때 정상 흐름")
    class NoConflictFlow {

        @Test
        @DisplayName("충돌 없으면 정책이 생성되고 인가 시스템이 리로드됨")
        void noConflictsNormalCreation() {
            PolicyDto dto = buildPolicyDto("safe-policy", Policy.Effect.ALLOW);

            when(policyConflictAnalyzer.analyze(any(Policy.class))).thenReturn(List.of());
            when(policyRepository.save(any(Policy.class)))
                    .thenAnswer(inv -> {
                        Policy p = inv.getArgument(0);
                        p.setId(50L);
                        return p;
                    });

            Policy result = service.createPolicy(dto);

            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("safe-policy");
            verify(policyRepository).save(any(Policy.class));
            verify(policyEnrichmentService).enrichPolicyWithFriendlyDescription(any(Policy.class));
            verify(authorizationManager).reload();
        }
    }

    // ── 4. detectConflicts API ───────────────────────────────────

    @Nested
    @DisplayName("detectConflicts API 조회")
    class DetectConflictsApi {

        @Test
        @DisplayName("detectConflicts는 분석 결과만 반환하고 저장하지 않음")
        void detectConflictsReturnsResults() {
            PolicyDto dto = buildPolicyDto("check-policy", Policy.Effect.ALLOW);
            List<PolicyConflictDto> expected = List.of(
                    new PolicyConflictDto(null, "check-policy", 1L, "deny-policy",
                            "Exact match", Severity.CRITICAL));

            when(policyConflictAnalyzer.analyze(any(Policy.class))).thenReturn(expected);

            List<PolicyConflictDto> result = service.detectConflicts(dto);

            assertThat(result).hasSize(1);
            assertThat(result.get(0).severity()).isEqualTo(Severity.CRITICAL);
            verify(policyRepository, never()).save(any());
        }

        @Test
        @DisplayName("수정 시나리오에서 detectConflicts가 정책 ID를 설정함")
        void detectConflictsSetsIdForUpdate() {
            PolicyDto dto = buildPolicyDto("update-check", Policy.Effect.ALLOW);
            dto.setId(7L);

            when(policyConflictAnalyzer.analyze(any(Policy.class))).thenReturn(List.of());

            service.detectConflicts(dto);

            ArgumentCaptor<Policy> captor = ArgumentCaptor.forClass(Policy.class);
            verify(policyConflictAnalyzer).analyze(captor.capture());
            assertThat(captor.getValue().getId()).isEqualTo(7L);
        }
    }

    // ── 5. 분산 캐시 브로드캐스트 ───────────────────────────────

    @Nested
    @DisplayName("분산 캐시 브로드캐스트")
    class DistributedBroadcast {

        @Test
        @DisplayName("정책 생성 후 리로드 신호를 브로드캐스트함")
        void createPolicyBroadcasts() {
            PolicyDto dto = buildPolicyDto("broadcast-policy", Policy.Effect.ALLOW);

            when(policyConflictAnalyzer.analyze(any(Policy.class))).thenReturn(List.of());
            when(policyRepository.save(any(Policy.class)))
                    .thenAnswer(inv -> {
                        Policy p = inv.getArgument(0);
                        p.setId(1L);
                        return p;
                    });

            service.createPolicy(dto);

            verify(policyReloadBroadcaster).broadcastReload();
        }

        @Test
        @DisplayName("정책 삭제 후 리로드 신호를 브로드캐스트함")
        void deletePolicyBroadcasts() {
            Policy policy = Policy.builder().id(1L).name("broadcast-test").effect(Policy.Effect.ALLOW).priority(100).isActive(true).build();
            when(policyRepository.findByIdWithDetails(1L)).thenReturn(Optional.of(policy));

            service.deletePolicy(1L);

            verify(policyReloadBroadcaster).broadcastReload();
        }

        @Test
        @DisplayName("PolicyReloadBroadcaster가 없어도 정상 동작함")
        void worksWithoutBroadcaster() {
            DefaultPolicyService serviceWithoutBroadcast = new DefaultPolicyService(
                    policyRepository, policyRetrievalPoint, authorizationManager,
                    policyEnrichmentService, eventBus, permissionRepository,
                    managedResourceRepository, centralAuditFacade, policyConflictAnalyzer,
                    policyValidationService, policyVersionService, policyImpactAnalyzer,
                    policySimulator, messageSource, aiPolicyValidator);

            PolicyDto dto = buildPolicyDto("no-broadcast", Policy.Effect.ALLOW);
            when(policyConflictAnalyzer.analyze(any(Policy.class))).thenReturn(List.of());
            when(policyRepository.save(any(Policy.class)))
                    .thenAnswer(inv -> {
                        Policy p = inv.getArgument(0);
                        p.setId(2L);
                        return p;
                    });

            Policy result = serviceWithoutBroadcast.createPolicy(dto);

            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("정책 승인 후 리로드 신호를 브로드캐스트함")
        void approvePolicyBroadcasts() {
            Policy policy = Policy.builder()
                    .id(3L).name("ai-policy").effect(Policy.Effect.ALLOW).priority(100)
                    .source(Policy.PolicySource.AI_GENERATED)
                    .approvalStatus(Policy.ApprovalStatus.PENDING).build();
            when(policyRepository.findByIdWithDetails(3L)).thenReturn(Optional.of(policy));
            when(policyRepository.save(any(Policy.class))).thenReturn(policy);
            when(aiPolicyValidator.validate(any(Policy.class))).thenReturn(
                    new AIPolicyValidationReport(List.of(), true, null));

            service.approvePolicy(3L, "admin");

            verify(policyReloadBroadcaster).broadcastReload();
        }
    }

    // ── 6. 혼합 심각도 충돌 ─────────────────────────────────────

    @Nested
    @DisplayName("혼합 심각도 충돌 처리")
    class MixedSeverity {

        @Test
        @DisplayName("CRITICAL + HIGH 혼합 시 예외에 전체 충돌 목록이 포함됨")
        void criticalAndHighConflicts() {
            PolicyDto dto = buildPolicyDto("mixed-policy", Policy.Effect.ALLOW);

            List<PolicyConflictDto> mixed = List.of(
                    new PolicyConflictDto(null, "mixed", 1L, "deny-exact",
                            "Exact match", Severity.CRITICAL),
                    new PolicyConflictDto(null, "mixed", 2L, "deny-wildcard",
                            "Wildcard overlap", Severity.HIGH));

            when(policyConflictAnalyzer.analyze(any(Policy.class))).thenReturn(mixed);

            assertThatThrownBy(() -> service.createPolicy(dto))
                    .isInstanceOf(PolicyConflictException.class)
                    .satisfies(ex -> {
                        PolicyConflictException pce = (PolicyConflictException) ex;
                        assertThat(pce.getConflicts()).hasSize(2);
                    });
        }

        @Test
        @DisplayName("HIGH + MEDIUM 혼합 시 HIGH 때문에 예외 발생")
        void highAndMediumBlocksByHigh() {
            PolicyDto dto = buildPolicyDto("warn-policy", Policy.Effect.ALLOW);

            List<PolicyConflictDto> mixed = List.of(
                    new PolicyConflictDto(null, "warn", 1L, "deny-wildcard",
                            "Wildcard overlap", Severity.HIGH),
                    new PolicyConflictDto(null, "warn", 2L, "deny-method",
                            "Method overlap", Severity.MEDIUM));

            when(policyConflictAnalyzer.analyze(any(Policy.class))).thenReturn(mixed);

            assertThatThrownBy(() -> service.createPolicy(dto))
                    .isInstanceOf(PolicyConflictException.class)
                    .satisfies(ex -> {
                        PolicyConflictException pce = (PolicyConflictException) ex;
                        assertThat(pce.getConflicts()).hasSize(2);
                    });
        }
    }

    // ── 7. 버전 자동 생성 ───────────────────────────────────────

    @Nested
    @DisplayName("정책 변경 시 버전 자동 생성")
    class VersionAutoCreation {

        @Test
        @DisplayName("정책 생성 시 CREATED 버전이 저장됨")
        void createPolicyCreatesVersion() {
            PolicyDto dto = buildPolicyDto("versioned", Policy.Effect.ALLOW);
            dto.setChangeReason("initial creation");

            when(policyConflictAnalyzer.analyze(any(Policy.class))).thenReturn(List.of());
            when(policyRepository.save(any(Policy.class)))
                    .thenAnswer(inv -> { Policy p = inv.getArgument(0); p.setId(1L); return p; });

            service.createPolicy(dto);

            verify(policyVersionService).createVersion(
                    any(Policy.class),
                    eq(PolicyVersion.ChangeType.CREATED),
                    eq("initial creation"));
        }

        @Test
        @DisplayName("정책 수정 시 변경 전 상태가 UPDATED 버전으로 저장됨")
        void updatePolicyCreatesVersion() {
            PolicyDto dto = buildPolicyDto("update-ver", Policy.Effect.ALLOW);
            dto.setId(10L);
            dto.setChangeReason("changed effect");

            Policy existing = Policy.builder()
                    .id(10L).name("update-ver").effect(Policy.Effect.ALLOW).priority(100).build();
            when(policyRepository.findByIdWithDetails(10L)).thenReturn(Optional.of(existing));
            when(policyConflictAnalyzer.analyze(any(Policy.class))).thenReturn(List.of());
            when(policyRepository.save(any(Policy.class))).thenReturn(existing);

            service.updatePolicy(dto);

            verify(policyVersionService).createVersion(
                    eq(existing),
                    eq(PolicyVersion.ChangeType.UPDATED),
                    eq("changed effect"));
        }

        @Test
        @DisplayName("정책 삭제 시 버전 이력도 함께 삭제됨")
        void deletePolicyDeletesVersions() {
            Policy existing = Policy.builder()
                    .id(5L).name("to-delete").effect(Policy.Effect.ALLOW).priority(100).build();
            when(policyRepository.findByIdWithDetails(5L)).thenReturn(Optional.of(existing));

            service.deletePolicy(5L, "no longer needed");

            verify(policyVersionService).deleteByPolicyId(5L);
            verify(policyRepository).deleteById(5L);
        }

        @Test
        @DisplayName("changeReason 없이 삭제해도 정상 동작")
        void deletePolicyWithoutReason() {
            Policy existing = Policy.builder()
                    .id(6L).name("to-delete").effect(Policy.Effect.ALLOW).priority(100).build();
            when(policyRepository.findByIdWithDetails(6L)).thenReturn(Optional.of(existing));

            service.deletePolicy(6L);

            verify(policyVersionService).deleteByPolicyId(6L);
            verify(policyRepository).deleteById(6L);
        }
    }

    // ── 8. 롤백 ─────────────────────────────────────────────────

    @Nested
    @DisplayName("정책 롤백")
    class Rollback {

        @Test
        @DisplayName("롤백 시 ROLLBACK 버전 1건만 생성됨 (UPDATED 중복 생성 안 됨)")
        void rollbackCreatesOnlyRollbackVersion() {
            PolicyDto snapshotDto = buildPolicyDto("rollback-target", Policy.Effect.ALLOW);
            PolicyVersion version = PolicyVersion.builder()
                    .policyId(10L).versionNumber(1).snapshotJson("{}").build();

            Policy existing = Policy.builder()
                    .id(10L).name("rollback-target").effect(Policy.Effect.DENY).priority(100).build();

            when(policyVersionService.getVersion(10L, 1)).thenReturn(Optional.of(version));
            when(policyVersionService.deserializeSnapshot(version)).thenReturn(Optional.of(snapshotDto));
            when(policyRepository.findByIdWithDetails(10L)).thenReturn(Optional.of(existing));
            when(policyConflictAnalyzer.analyze(any(Policy.class))).thenReturn(List.of());
            when(policyRepository.save(any(Policy.class))).thenReturn(existing);

            service.rollbackPolicy(10L, 1, "revert mistake");

            // ROLLBACK 1건만 생성되어야 함 (UPDATED 중복 없음)
            verify(policyVersionService, times(1)).createVersion(
                    any(Policy.class),
                    eq(PolicyVersion.ChangeType.ROLLBACK),
                    contains("msg.policy.version.rollback.reason"));
            // UPDATED 버전은 생성되지 않아야 함
            verify(policyVersionService, never()).createVersion(
                    any(Policy.class),
                    eq(PolicyVersion.ChangeType.UPDATED),
                    any());
        }

        @Test
        @DisplayName("존재하지 않는 버전으로 롤백 시 예외 발생")
        void rollbackNonExistentVersion() {
            when(policyVersionService.getVersion(10L, 99)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.rollbackPolicy(10L, 99, "reason"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("msg.policy.version.not.found");
        }
    }
}
