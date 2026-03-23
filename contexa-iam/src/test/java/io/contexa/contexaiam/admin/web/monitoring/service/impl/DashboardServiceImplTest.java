package io.contexa.contexaiam.admin.web.monitoring.service.impl;

import io.contexa.contexaiam.admin.support.context.dto.RecentActivityDto;
import io.contexa.contexaiam.admin.support.context.service.UserContextService;
import io.contexa.contexaiam.admin.web.monitoring.dto.*;
import io.contexa.contexaiam.admin.web.monitoring.service.DashboardService;
import io.contexa.contexaiam.admin.web.monitoring.service.DashboardServiceImpl;
import io.contexa.contexaiam.admin.web.monitoring.service.PermissionMatrixService;
import io.contexa.contexaiam.admin.web.monitoring.service.SecurityScoreCalculator;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DashboardServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private GroupRepository groupRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private PolicyRepository policyRepository;

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private RoleHierarchyRepository roleHierarchyRepository;

    @Mock
    private UserContextService userContextService;

    @Mock
    private SecurityScoreCalculator securityScoreCalculator;

    @Mock
    private PermissionMatrixService permissionMatrixService;

    @Mock
    private ManagedResourceRepository managedResourceRepository;

    @Mock
    private BlockedUserJpaRepository blockedUserJpaRepository;

    @InjectMocks
    private DashboardServiceImpl service;

    @BeforeEach
    void setUpSecurityContext() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("admin", "password"));
    }

    // ===== Helper methods =====

    private void stubRepositoryCounts(long users, long groups, long roles, long permissions, long policies) {
        when(userRepository.count()).thenReturn(users);
        when(groupRepository.count()).thenReturn(groups);
        when(roleRepository.count()).thenReturn(roles);
        when(permissionRepository.count()).thenReturn(permissions);
        when(policyRepository.count()).thenReturn(policies);
    }

    private void stubAllAuditLogMethods() {
        when(auditLogRepository.countAllowedSince(any())).thenReturn(100L);
        when(auditLogRepository.countDeniedAttemptsSince(any())).thenReturn(5L);
        when(auditLogRepository.countByEventCategoryAndTimestampAfter(any(), any())).thenReturn(10L);
        when(auditLogRepository.countAdminOverridesSince(any())).thenReturn(2L);
        when(auditLogRepository.countSecurityErrorsSince(any())).thenReturn(1L);
        when(auditLogRepository.countAfterHoursAccessSince(any())).thenReturn(3L);
        when(auditLogRepository.countDistinctIpsSince(any())).thenReturn(15L);
        when(auditLogRepository.avgRiskScoreSince(any())).thenReturn(0.35);
        when(auditLogRepository.countZeroTrustDecisionSince(any(), any())).thenReturn(20L);
        when(auditLogRepository.countZeroTrustTotalSince(any())).thenReturn(50L);
        when(auditLogRepository.countPolicyChangesSince(any())).thenReturn(4L);
        when(auditLogRepository.countIamChangesSince(any())).thenReturn(6L);
        when(auditLogRepository.findRecentThreatEvents(any())).thenReturn(Collections.emptyList());
        when(auditLogRepository.findByCreatedAtAfter(any())).thenReturn(Collections.emptyList());
    }

    private void stubAllDependencies() {
        stubRepositoryCounts(50L, 10L, 20L, 100L, 30L);
        stubAllAuditLogMethods();

        when(policyRepository.countByIsActiveTrue()).thenReturn(25L);
        when(userRepository.countByMfaEnabled(true)).thenReturn(40L);
        when(userRepository.countByMfaEnabled(false)).thenReturn(10L);
        when(userRepository.findAdminsWithMfaDisabled()).thenReturn(Collections.emptyList());

        when(securityScoreCalculator.calculate()).thenReturn(
                new SecurityScoreDto(85, "GOOD", Collections.emptyList()));
        when(permissionMatrixService.getPermissionMatrix(any())).thenReturn(
                new PermissionMatrixDto(Collections.emptyList(), Collections.emptyList(), Collections.emptyMap()));
        when(userContextService.getRecentActivities(any())).thenReturn(Collections.emptyList());

        when(managedResourceRepository.count()).thenReturn(200L);
        when(managedResourceRepository.countByStatus(ManagedResource.Status.POLICY_CONNECTED)).thenReturn(150L);
        when(managedResourceRepository.countByStatus(ManagedResource.Status.PERMISSION_CREATED)).thenReturn(30L);

        when(blockedUserJpaRepository.countByStatus(BlockedUserStatus.BLOCKED)).thenReturn(3L);
        when(blockedUserJpaRepository.countByStatus(BlockedUserStatus.UNBLOCK_REQUESTED)).thenReturn(1L);
        when(blockedUserJpaRepository.countByStatus(BlockedUserStatus.TIMEOUT_RESPONDED)).thenReturn(0L);
        when(blockedUserJpaRepository.countByStatus(BlockedUserStatus.MFA_FAILED)).thenReturn(2L);
        when(blockedUserJpaRepository.countByStatus(BlockedUserStatus.RESOLVED)).thenReturn(10L);
        when(blockedUserJpaRepository.findTop5ByStatusInOrderByBlockedAtDesc(any())).thenReturn(Collections.emptyList());

        when(policyRepository.countBySource(any())).thenReturn(5L);
        when(policyRepository.countBySourceInAndApprovalStatus(any(), any())).thenReturn(2L);
        when(policyRepository.calculateAverageConfidenceScoreForAIPolicies()).thenReturn(0.75);
        when(policyRepository.findTop5ByOrderByCreatedAtDesc()).thenReturn(Collections.emptyList());
        when(roleHierarchyRepository.existsByIsActiveTrue()).thenReturn(true);
    }

    // =========================================================================
    // getDashboardData
    // =========================================================================

    @Nested
    @DisplayName("getDashboardData")
    class GetDashboardData {

        @Test
        @DisplayName("should return non-null dashboard data")
        void shouldReturnNonNull() {
            stubAllDependencies();

            DashboardDto result = service.getDashboardData();

            assertThat(result).isNotNull();
        }

        @Test
        @DisplayName("should have correct statistics counts from repositories")
        void shouldHaveCorrectStatistics() {
            stubAllDependencies();

            DashboardDto result = service.getDashboardData();

            assertThat(result.statistics()).isNotNull();
            assertThat(result.statistics().totalUsers()).isEqualTo(50L);
            assertThat(result.statistics().totalGroups()).isEqualTo(10L);
            assertThat(result.statistics().totalRoles()).isEqualTo(20L);
            assertThat(result.statistics().totalPermissions()).isEqualTo(100L);
            assertThat(result.statistics().totalPolicies()).isEqualTo(30L);
        }

        @Test
        @DisplayName("should pass through security score from calculator")
        void shouldPassThroughSecurityScore() {
            stubAllDependencies();

            DashboardDto result = service.getDashboardData();

            assertThat(result.securityScore()).isNotNull();
            assertThat(result.securityScore().score()).isEqualTo(85);
        }

        @Test
        @DisplayName("should include blocked user counts")
        void shouldIncludeBlockedUserCounts() {
            stubAllDependencies();

            DashboardDto result = service.getDashboardData();

            assertThat(result.blockedUserCount()).isEqualTo(3L);
            assertThat(result.unblockRequestedCount()).isEqualTo(1L);
            assertThat(result.mfaFailedCount()).isEqualTo(2L);
            assertThat(result.resolvedCount()).isEqualTo(10L);
        }

        @Test
        @DisplayName("should include resource counts")
        void shouldIncludeResourceCounts() {
            stubAllDependencies();

            DashboardDto result = service.getDashboardData();

            assertThat(result.resourceTotal()).isEqualTo(200L);
            assertThat(result.resourceProtected()).isEqualTo(150L);
            assertThat(result.resourceAwaiting()).isEqualTo(30L);
        }

        @Test
        @DisplayName("should include 24h audit activity counts")
        void shouldInclude24hAuditCounts() {
            stubAllDependencies();

            DashboardDto result = service.getDashboardData();

            assertThat(result.allowCount24h()).isEqualTo(100L);
            assertThat(result.denyCount24h()).isEqualTo(5L);
        }
    }
}
