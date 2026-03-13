package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.domain.AdminOverride;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AdminOverrideServiceTest {

    @Mock
    private SecurityLearningService securityLearningService;

    @Mock
    private ZeroTrustActionRepository actionRedisRepository;

    @Mock
    private DistributedLockService lockService;

    @Mock
    private CentralAuditFacade centralAuditFacade;

    private AdminOverrideService adminOverrideService;

    @BeforeEach
    void setUp() {
        adminOverrideService = new AdminOverrideService(
                securityLearningService, actionRedisRepository, lockService, centralAuditFacade);

        // Default: executeWithLock executes the operation directly
        when(lockService.executeWithLock(anyString(), any(Duration.class), any()))
                .thenAnswer(invocation -> {
                    DistributedLockService.LockableOperation<?> operation = invocation.getArgument(2);
                    return operation.execute();
                });
    }

    @Test
    @DisplayName("Normal approval calls approveOverrideAtomically for non-blocking action")
    void approve_normalFlow_callsApproveOverrideAtomically() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("192.168.1.1")
                .userId("user1")
                .build();

        // when
        AdminOverride result = adminOverrideService.approve(
                "req-1", "user1", "admin1",
                "BLOCK", 0.9, 0.85,
                "ALLOW", "Verified legitimate user",
                event);

        // then
        assertThat(result).isNotNull();
        assertThat(result.isApproved()).isTrue();
        assertThat(result.getOverriddenAction()).isEqualTo("ALLOW");
        assertThat(result.getReason()).isEqualTo("Verified legitimate user");
        verify(actionRedisRepository).approveOverrideAtomically("user1", ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("Approval triggers baseline update when canUpdateBaseline is true")
    void approve_allowAction_triggersBaselineUpdate() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user1")
                .build();

        // when
        adminOverrideService.approve(
                "req-1", "user1", "admin1",
                "BLOCK", 0.9, 0.85,
                "ALLOW", "Safe user",
                event);

        // then
        verify(lockService).executeWithLock(eq("baseline:update:user1"), any(Duration.class), any());
        verify(securityLearningService).learnAndStore(eq("user1"), any(), any());
    }

    @Test
    @DisplayName("Approval creates audit record")
    void approve_normalFlow_createsAuditRecord() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp("10.0.0.1")
                .userId("user1")
                .build();

        // when
        adminOverrideService.approve(
                "req-1", "user1", "admin1",
                "BLOCK", 0.9, 0.85,
                "ALLOW", "Legitimate activity",
                event);

        // then
        ArgumentCaptor<AuditRecord> captor = ArgumentCaptor.forClass(AuditRecord.class);
        verify(centralAuditFacade).recordAsync(captor.capture());

        AuditRecord auditRecord = captor.getValue();
        assertThat(auditRecord.getPrincipalName()).isEqualTo("admin1");
        assertThat(auditRecord.getAction()).isEqualTo("APPROVE");
        assertThat(auditRecord.getClientIp()).isEqualTo("10.0.0.1");
        assertThat(auditRecord.getResourceIdentifier()).isEqualTo("user1");
    }

    @Test
    @DisplayName("Approval without reason throws IllegalArgumentException")
    void approve_noReason_throwsException() {
        // when & then
        assertThatThrownBy(() -> adminOverrideService.approve(
                "req-1", "user1", "admin1",
                "BLOCK", 0.9, 0.85,
                "ALLOW", null,
                null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Reason is required");

        assertThatThrownBy(() -> adminOverrideService.approve(
                "req-1", "user1", "admin1",
                "BLOCK", 0.9, 0.85,
                "ALLOW", "   ",
                null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Reason is required");
    }

    @Test
    @DisplayName("Approval without requestId throws IllegalArgumentException")
    void approve_noRequestId_throwsException() {
        // when & then
        assertThatThrownBy(() -> adminOverrideService.approve(
                null, "user1", "admin1",
                "BLOCK", 0.9, 0.85,
                "ALLOW", "Valid reason",
                null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requestId is required");
    }

    @Test
    @DisplayName("BLOCK action does not call approveOverrideAtomically, calls saveAction instead")
    void approve_blockAction_callsSaveActionNotApprove() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user1")
                .build();

        // when
        adminOverrideService.approve(
                "req-1", "user1", "admin1",
                "ALLOW", 0.1, 0.95,
                "BLOCK", "Suspicious activity detected",
                event);

        // then
        verify(actionRedisRepository, never()).approveOverrideAtomically(anyString(), any());
        verify(actionRedisRepository).saveAction(eq("user1"), eq(ZeroTrustAction.BLOCK), any());
    }

    @Test
    @DisplayName("ESCALATE action does not call approveOverrideAtomically, calls saveAction instead")
    void approve_escalateAction_callsSaveActionNotApprove() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user1")
                .build();

        // when
        adminOverrideService.approve(
                "req-1", "user1", "admin1",
                "ALLOW", 0.2, 0.9,
                "ESCALATE", "Needs further review",
                event);

        // then
        verify(actionRedisRepository, never()).approveOverrideAtomically(anyString(), any());
        verify(actionRedisRepository).saveAction(eq("user1"), eq(ZeroTrustAction.ESCALATE), any());
    }

    @Test
    @DisplayName("BLOCK override does not trigger baseline update")
    void approve_blockAction_doesNotTriggerBaselineUpdate() {
        // given
        SecurityEvent event = SecurityEvent.builder()
                .userId("user1")
                .build();

        // when
        adminOverrideService.approve(
                "req-1", "user1", "admin1",
                "ALLOW", 0.1, 0.95,
                "BLOCK", "Suspicious activity",
                event);

        // then - canUpdateBaseline is false for BLOCK, so no learnAndStore
        verify(securityLearningService, never()).learnAndStore(anyString(), any(), any());
    }
}
