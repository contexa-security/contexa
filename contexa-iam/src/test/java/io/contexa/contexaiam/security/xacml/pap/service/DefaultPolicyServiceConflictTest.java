package io.contexa.contexaiam.security.xacml.pap.service;

import io.contexa.contexaiam.common.event.service.IntegrationEventBus;
import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictAnalyzer;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictException;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto.Severity;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.prp.PolicyRetrievalPoint;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexacommon.repository.PermissionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

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
    @Mock private PolicyReloadBroadcaster policyReloadBroadcaster;

    private DefaultPolicyService service;

    @BeforeEach
    void setUp() {
        service = new DefaultPolicyService(
                policyRepository, policyRetrievalPoint, authorizationManager,
                policyEnrichmentService, eventBus, permissionRepository,
                managedResourceRepository, centralAuditFacade, policyConflictAnalyzer);
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
                    .hasMessageContaining("Critical policy conflicts detected")
                    .satisfies(ex -> {
                        PolicyConflictException pce = (PolicyConflictException) ex;
                        assertThat(pce.getConflicts()).hasSize(1);
                        assertThat(pce.getConflicts().getFirst().severity()).isEqualTo(Severity.CRITICAL);
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
            when(policyRepository.findByIdWithDetails(10L)).thenReturn(java.util.Optional.of(existing));

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
    @DisplayName("CRITICAL 미만 충돌은 경고만 발생")
    class NonCriticalConflictWarning {

        @Test
        @DisplayName("HIGH 충돌은 생성을 허용하고 경고만 기록함")
        void highConflictAllowsCreation() {
            PolicyDto dto = buildPolicyDto("allow-path", Policy.Effect.ALLOW);

            when(policyConflictAnalyzer.analyze(any(Policy.class)))
                    .thenReturn(List.of(new PolicyConflictDto(
                            null, "allow-path", 1L, "deny-wildcard",
                            "Wildcard overlap", Severity.HIGH)));
            when(policyRepository.save(any(Policy.class)))
                    .thenAnswer(inv -> {
                        Policy p = inv.getArgument(0);
                        p.setId(99L);
                        return p;
                    });

            Policy result = service.createPolicy(dto);

            assertThat(result).isNotNull();
            verify(policyRepository).save(any(Policy.class));
        }

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
            assertThat(result.getFirst().severity()).isEqualTo(Severity.CRITICAL);
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
            when(policyRepository.findByIdWithDetails(1L)).thenReturn(java.util.Optional.empty());
            when(policyRepository.findById(1L)).thenReturn(java.util.Optional.empty());

            service.deletePolicy(1L);

            verify(policyReloadBroadcaster).broadcastReload();
        }

        @Test
        @DisplayName("PolicyReloadBroadcaster가 없어도 정상 동작함")
        void worksWithoutBroadcaster() {
            DefaultPolicyService serviceWithoutBroadcast = new DefaultPolicyService(
                    policyRepository, policyRetrievalPoint, authorizationManager,
                    policyEnrichmentService, eventBus, permissionRepository,
                    managedResourceRepository, centralAuditFacade, policyConflictAnalyzer);

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
            when(policyRepository.findByIdWithDetails(3L)).thenReturn(java.util.Optional.of(policy));
            when(policyRepository.save(any(Policy.class))).thenReturn(policy);

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
        @DisplayName("HIGH + MEDIUM만 있으면 예외 없이 생성됨")
        void onlyHighAndMedium() {
            PolicyDto dto = buildPolicyDto("warn-policy", Policy.Effect.ALLOW);

            List<PolicyConflictDto> nonCritical = List.of(
                    new PolicyConflictDto(null, "warn", 1L, "deny-wildcard",
                            "Wildcard overlap", Severity.HIGH),
                    new PolicyConflictDto(null, "warn", 2L, "deny-method",
                            "Method overlap", Severity.MEDIUM));

            when(policyConflictAnalyzer.analyze(any(Policy.class))).thenReturn(nonCritical);
            when(policyRepository.save(any(Policy.class)))
                    .thenAnswer(inv -> {
                        Policy p = inv.getArgument(0);
                        p.setId(1L);
                        return p;
                    });

            Policy result = service.createPolicy(dto);

            assertThat(result).isNotNull();
        }
    }
}
