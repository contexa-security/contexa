package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.monitoring.dto.SecurityScoreDto;
import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityScoreCalculatorImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private RoleHierarchyRepository roleHierarchyRepository;

    @Mock
    private AuditLogRepository auditLogRepository;

    @InjectMocks
    private SecurityScoreCalculatorImpl calculator;

    @Nested
    @DisplayName("Admin MFA factor (weight 0.35)")
    class AdminMfaFactor {

        @Test
        @DisplayName("should score 100 when all admins have MFA enabled")
        void shouldScore100WhenAllAdminsHaveMfa() {
            // given
            stubAllFactorsDefault();
            when(userRepository.countByRoles("ADMIN")).thenReturn(10L);
            when(userRepository.countByMfaEnabledAndRoles(false, "ADMIN")).thenReturn(0L);

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor adminFactor = findFactor(result, "Admin MFA Activation Rate");
            assertThat(adminFactor.value()).isEqualTo(100);
            assertThat(adminFactor.weight()).isEqualTo(0.35);
        }

        @Test
        @DisplayName("should score 50 when half of admins have MFA enabled")
        void shouldScore50WhenHalfAdminsHaveMfa() {
            // given
            stubAllFactorsDefault();
            when(userRepository.countByRoles("ADMIN")).thenReturn(10L);
            when(userRepository.countByMfaEnabledAndRoles(false, "ADMIN")).thenReturn(5L);

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor adminFactor = findFactor(result, "Admin MFA Activation Rate");
            assertThat(adminFactor.value()).isEqualTo(50);
        }

        @Test
        @DisplayName("should score 100 when no admin accounts exist")
        void shouldScore100WhenNoAdmins() {
            // given
            stubAllFactorsDefault();
            when(userRepository.countByRoles("ADMIN")).thenReturn(0L);

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor adminFactor = findFactor(result, "Admin MFA Activation Rate");
            assertThat(adminFactor.value()).isEqualTo(100);
        }
    }

    @Nested
    @DisplayName("User MFA factor (weight 0.20)")
    class UserMfaFactor {

        @Test
        @DisplayName("should score based on MFA-enabled user ratio")
        void shouldScoreBasedOnMfaRatio() {
            // given
            stubAllFactorsDefault();
            when(userRepository.count()).thenReturn(100L);
            when(userRepository.countByMfaEnabled(true)).thenReturn(75L);

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor userFactor = findFactor(result, "User MFA Activation Rate");
            assertThat(userFactor.value()).isEqualTo(75);
            assertThat(userFactor.weight()).isEqualTo(0.20);
        }

        @Test
        @DisplayName("should score 100 when no users exist")
        void shouldScore100WhenNoUsers() {
            // given
            stubAllFactorsDefault();
            when(userRepository.count()).thenReturn(0L);

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor userFactor = findFactor(result, "User MFA Activation Rate");
            assertThat(userFactor.value()).isEqualTo(100);
        }
    }

    @Nested
    @DisplayName("Role Hierarchy factor (weight 0.15)")
    class RoleHierarchyFactor {

        @Test
        @DisplayName("should score 100 when active role hierarchy exists")
        void shouldScore100WhenHierarchyExists() {
            // given
            stubAllFactorsDefault();
            when(roleHierarchyRepository.findByIsActiveTrue()).thenReturn(Optional.of(mock(RoleHierarchyEntity.class)));

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor factor = findFactor(result, "Role Hierarchy Status");
            assertThat(factor.value()).isEqualTo(100);
            assertThat(factor.weight()).isEqualTo(0.15);
        }

        @Test
        @DisplayName("should score 0 when no active role hierarchy exists")
        void shouldScore0WhenNoHierarchy() {
            // given
            stubAllFactorsDefault();
            when(roleHierarchyRepository.findByIsActiveTrue()).thenReturn(Optional.empty());

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor factor = findFactor(result, "Role Hierarchy Status");
            assertThat(factor.value()).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("AI Policy Approval factor (weight 0.15)")
    class AiPolicyApprovalFactor {

        @Test
        @DisplayName("should score 100 when no AI policies exist")
        void shouldScore100WhenNoAiPolicies() {
            // given
            stubAllFactorsDefault();
            when(policyRepository.countBySourceIn(anyList())).thenReturn(0L);

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor factor = findFactor(result, "AI Policy Approval Rate");
            assertThat(factor.value()).isEqualTo(100);
        }

        @Test
        @DisplayName("should calculate approval rate based on approved and not-required AI policies")
        void shouldCalculateApprovalRate() {
            // given
            stubAllFactorsDefault();
            when(policyRepository.countBySourceIn(anyList())).thenReturn(20L);
            when(policyRepository.countBySourceInAndApprovalStatus(anyList(), eq(Policy.ApprovalStatus.APPROVED)))
                    .thenReturn(12L);
            when(policyRepository.countBySourceInAndApprovalStatus(anyList(), eq(Policy.ApprovalStatus.NOT_REQUIRED)))
                    .thenReturn(4L);

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor factor = findFactor(result, "AI Policy Approval Rate");
            // (12 + 4) * 100 / 20 = 80
            assertThat(factor.value()).isEqualTo(80);
        }
    }

    @Nested
    @DisplayName("Access Deny Rate factor (weight 0.15)")
    class AccessDenyRateFactor {

        @Test
        @DisplayName("should score 100 when no recent audit logs")
        void shouldScore100WhenNoLogs() {
            // given
            stubAllFactorsDefault();
            when(auditLogRepository.findByCreatedAtAfter(any())).thenReturn(Collections.emptyList());

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor factor = findFactor(result, "Access Deny Rate (Inverted)");
            assertThat(factor.value()).isEqualTo(100);
        }

        @Test
        @DisplayName("should score 100 when deny rate is <= 1%")
        void shouldScore100WhenDenyRateBelow1Percent() {
            // given
            stubAllFactorsDefault();
            List<AuditLog> logs = createAuditLogs(1000, 5); // 0.5% deny rate
            when(auditLogRepository.findByCreatedAtAfter(any())).thenReturn(logs);

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor factor = findFactor(result, "Access Deny Rate (Inverted)");
            assertThat(factor.value()).isEqualTo(100);
        }

        @Test
        @DisplayName("should score 80 when deny rate is between 1% and 5%")
        void shouldScore80WhenDenyRate1To5Percent() {
            // given
            stubAllFactorsDefault();
            List<AuditLog> logs = createAuditLogs(100, 3); // 3% deny rate
            when(auditLogRepository.findByCreatedAtAfter(any())).thenReturn(logs);

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor factor = findFactor(result, "Access Deny Rate (Inverted)");
            assertThat(factor.value()).isEqualTo(80);
        }

        @Test
        @DisplayName("should score 20 when deny rate exceeds 20%")
        void shouldScore20WhenDenyRateExceeds20Percent() {
            // given
            stubAllFactorsDefault();
            List<AuditLog> logs = createAuditLogs(100, 30); // 30% deny rate
            when(auditLogRepository.findByCreatedAtAfter(any())).thenReturn(logs);

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            SecurityScoreDto.ScoreFactor factor = findFactor(result, "Access Deny Rate (Inverted)");
            assertThat(factor.value()).isEqualTo(20);
        }
    }

    @Nested
    @DisplayName("Final score and summary")
    class FinalScoreAndSummary {

        @Test
        @DisplayName("should round final weighted score correctly")
        void shouldRoundFinalScore() {
            // given - all factors score 100
            when(userRepository.countByRoles("ADMIN")).thenReturn(0L);
            when(userRepository.count()).thenReturn(0L);
            when(userRepository.countByMfaEnabled(true)).thenReturn(0L);
            when(roleHierarchyRepository.findByIsActiveTrue()).thenReturn(Optional.of(mock(RoleHierarchyEntity.class)));
            when(policyRepository.countBySourceIn(anyList())).thenReturn(0L);
            when(policyRepository.countBySourceInAndApprovalStatus(anyList(), any())).thenReturn(0L);
            when(auditLogRepository.findByCreatedAtAfter(any())).thenReturn(Collections.emptyList());

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            // 100*0.35 + 100*0.20 + 100*0.15 + 100*0.15 + 100*0.15 = 100
            assertThat(result.score()).isEqualTo(100);
        }

        @Test
        @DisplayName("should generate 'Excellent' summary for score >= 90")
        void shouldGenerateExcellentSummary() {
            // given - all factors score 100
            stubPerfectScores();

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            assertThat(result.summary()).contains("Excellent");
        }

        @Test
        @DisplayName("should generate 'Good' summary for score >= 80")
        void shouldGenerateGoodSummary() {
            // given
            when(userRepository.countByRoles("ADMIN")).thenReturn(10L);
            when(userRepository.countByMfaEnabledAndRoles(false, "ADMIN")).thenReturn(3L);
            when(userRepository.count()).thenReturn(100L);
            when(userRepository.countByMfaEnabled(true)).thenReturn(80L);
            when(roleHierarchyRepository.findByIsActiveTrue()).thenReturn(Optional.of(mock(RoleHierarchyEntity.class)));
            when(policyRepository.countBySourceIn(anyList())).thenReturn(0L);
            when(policyRepository.countBySourceInAndApprovalStatus(anyList(), any())).thenReturn(0L);
            when(auditLogRepository.findByCreatedAtAfter(any())).thenReturn(Collections.emptyList());

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            // Admin: 70*0.35=24.5, User: 80*0.20=16, Hierarchy: 100*0.15=15, Policy: 100*0.15=15, Deny: 100*0.15=15 = 85.5 => 86
            assertThat(result.score()).isGreaterThanOrEqualTo(80);
            assertThat(result.summary()).contains("Good");
        }

        @Test
        @DisplayName("should generate 'improvements needed' summary for score >= 60")
        void shouldGenerateImprovementsNeededSummary() {
            // given
            when(userRepository.countByRoles("ADMIN")).thenReturn(10L);
            when(userRepository.countByMfaEnabledAndRoles(false, "ADMIN")).thenReturn(10L);
            when(userRepository.count()).thenReturn(100L);
            when(userRepository.countByMfaEnabled(true)).thenReturn(80L);
            when(roleHierarchyRepository.findByIsActiveTrue()).thenReturn(Optional.of(mock(RoleHierarchyEntity.class)));
            when(policyRepository.countBySourceIn(anyList())).thenReturn(0L);
            when(policyRepository.countBySourceInAndApprovalStatus(anyList(), any())).thenReturn(0L);
            when(auditLogRepository.findByCreatedAtAfter(any())).thenReturn(Collections.emptyList());

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            // Admin: 0*0.35=0, User: 80*0.20=16, Hierarchy: 100*0.15=15, Policy: 100*0.15=15, Deny: 100*0.15=15 = 61
            assertThat(result.score()).isGreaterThanOrEqualTo(60);
            assertThat(result.score()).isLessThan(80);
            assertThat(result.summary()).containsIgnoringCase("improvement");
        }

        @Test
        @DisplayName("should generate 'Critical' summary for score < 40")
        void shouldGenerateCriticalSummary() {
            // given - make all factors score low
            when(userRepository.countByRoles("ADMIN")).thenReturn(10L);
            when(userRepository.countByMfaEnabledAndRoles(false, "ADMIN")).thenReturn(10L);
            when(userRepository.count()).thenReturn(100L);
            when(userRepository.countByMfaEnabled(true)).thenReturn(0L);
            when(roleHierarchyRepository.findByIsActiveTrue()).thenReturn(Optional.empty());
            when(policyRepository.countBySourceIn(anyList())).thenReturn(10L);
            when(policyRepository.countBySourceInAndApprovalStatus(anyList(), eq(Policy.ApprovalStatus.APPROVED)))
                    .thenReturn(0L);
            when(policyRepository.countBySourceInAndApprovalStatus(anyList(), eq(Policy.ApprovalStatus.NOT_REQUIRED)))
                    .thenReturn(0L);
            List<AuditLog> logs = createAuditLogs(100, 30);
            when(auditLogRepository.findByCreatedAtAfter(any())).thenReturn(logs);

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            // Admin: 0*0.35=0, User: 0*0.20=0, Hierarchy: 0*0.15=0, Policy: 0*0.15=0, Deny: 20*0.15=3 = 3
            assertThat(result.score()).isLessThan(40);
            assertThat(result.summary()).containsIgnoringCase("Critical");
        }

        @Test
        @DisplayName("should always return exactly 5 score factors")
        void shouldReturnFiveFactors() {
            // given
            stubPerfectScores();

            // when
            SecurityScoreDto result = calculator.calculate();

            // then
            assertThat(result.factors()).hasSize(5);
        }
    }

    // -- helper methods --

    private void stubAllFactorsDefault() {
        when(userRepository.countByRoles("ADMIN")).thenReturn(0L);
        when(userRepository.count()).thenReturn(0L);
        when(userRepository.countByMfaEnabled(true)).thenReturn(0L);
        when(roleHierarchyRepository.findByIsActiveTrue()).thenReturn(Optional.of(mock(RoleHierarchyEntity.class)));
        when(policyRepository.countBySourceIn(anyList())).thenReturn(0L);
        when(policyRepository.countBySourceInAndApprovalStatus(anyList(), any())).thenReturn(0L);
        when(auditLogRepository.findByCreatedAtAfter(any())).thenReturn(Collections.emptyList());
    }

    private void stubPerfectScores() {
        when(userRepository.countByRoles("ADMIN")).thenReturn(0L);
        when(userRepository.count()).thenReturn(0L);
        when(userRepository.countByMfaEnabled(true)).thenReturn(0L);
        when(roleHierarchyRepository.findByIsActiveTrue()).thenReturn(Optional.of(mock(RoleHierarchyEntity.class)));
        when(policyRepository.countBySourceIn(anyList())).thenReturn(0L);
        when(policyRepository.countBySourceInAndApprovalStatus(anyList(), any())).thenReturn(0L);
        when(auditLogRepository.findByCreatedAtAfter(any())).thenReturn(Collections.emptyList());
    }

    private SecurityScoreDto.ScoreFactor findFactor(SecurityScoreDto dto, String name) {
        return dto.factors().stream()
                .filter(f -> f.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Factor not found: " + name));
    }

    private List<AuditLog> createAuditLogs(int total, int denyCount) {
        List<AuditLog> logs = new java.util.ArrayList<>();
        for (int i = 0; i < total; i++) {
            AuditLog log = mock(AuditLog.class);
            if (i < denyCount) {
                when(log.getDecision()).thenReturn("DENY");
            } else {
                when(log.getDecision()).thenReturn("ALLOW");
            }
            logs.add(log);
        }
        return logs;
    }
}
