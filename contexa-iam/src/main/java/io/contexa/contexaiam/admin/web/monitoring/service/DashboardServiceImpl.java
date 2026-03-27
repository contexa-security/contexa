package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexaiam.admin.web.monitoring.dto.DashboardDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.RiskIndicatorDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.StatisticsDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.PolicyStatusDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.RecentPolicyDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.AccessTrendDto;
import io.contexa.contexaiam.admin.support.context.service.UserContextService;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

@RequiredArgsConstructor
public class DashboardServiceImpl implements DashboardService {

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final PolicyRepository policyRepository;
    private final AuditLogRepository auditLogRepository;
    private final RoleHierarchyRepository roleHierarchyRepository;
    private final UserContextService userContextService;
    private final SecurityScoreCalculator securityScoreCalculator;
    private final PermissionMatrixService permissionMatrixService;
    private final ManagedResourceRepository managedResourceRepository;
    private final BlockedUserJpaRepository blockedUserJpaRepository;

    @Override
    @Transactional(readOnly = true)
    public DashboardDto getDashboardData() {
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        LocalDateTime since24h = LocalDateTime.now().minusHours(24);

        // ManagedResource: 3 queries -> 1 GROUP BY
        Map<ManagedResource.Status, Long> resourceCounts = new EnumMap<>(ManagedResource.Status.class);
        long resourceTotal = 0;
        for (Object[] row : managedResourceRepository.countGroupByStatus()) {
            ManagedResource.Status status = (ManagedResource.Status) row[0];
            long count = (Long) row[1];
            resourceCounts.put(status, count);
            resourceTotal += count;
        }

        // BlockedUser: 5 queries -> 1 GROUP BY
        Map<BlockedUserStatus, Long> blockedCounts = new EnumMap<>(BlockedUserStatus.class);
        for (Object[] row : blockedUserJpaRepository.countGroupByStatus()) {
            blockedCounts.put((BlockedUserStatus) row[0], (Long) row[1]);
        }

        // AuditLog EventCategory: 3 queries -> 1 GROUP BY
        Map<String, Long> eventCatCounts = new HashMap<>();
        for (Object[] row : auditLogRepository.countByEventCategoriesGrouped(since24h,
                List.of("AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILURE", "SECURITY_DECISION"))) {
            eventCatCounts.put((String) row[0], (Long) row[1]);
        }

        // ZeroTrust Decision: 5 queries -> 1 GROUP BY
        Map<String, Long> ztCounts = new HashMap<>();
        long ztTotal = 0;
        for (Object[] row : auditLogRepository.countZeroTrustGroupByDecision(since24h)) {
            String decision = (String) row[0];
            long count = (Long) row[1];
            ztCounts.put(decision, count);
            ztTotal += count;
        }

        // Policy counts: computed once, shared between buildStatistics and buildPolicyStatus
        long policyTotal = policyRepository.count();
        long policyActive = policyRepository.countByIsActiveTrue();

        return new DashboardDto(
                buildStatistics(policyTotal, policyActive),
                userContextService.getRecentActivities(currentUsername),
                analyzeRiskIndicators(),
                securityScoreCalculator.calculate(),
                permissionMatrixService.getPermissionMatrix(null),
                buildPolicyStatus(policyTotal, policyActive),
                buildAccessTrends(),
                resourceTotal,
                resourceCounts.getOrDefault(ManagedResource.Status.POLICY_CONNECTED, 0L),
                resourceCounts.getOrDefault(ManagedResource.Status.PERMISSION_CREATED, 0L),
                blockedCounts.getOrDefault(BlockedUserStatus.BLOCKED, 0L),
                blockedCounts.getOrDefault(BlockedUserStatus.UNBLOCK_REQUESTED, 0L),
                blockedCounts.getOrDefault(BlockedUserStatus.TIMEOUT_RESPONDED, 0L),
                blockedCounts.getOrDefault(BlockedUserStatus.MFA_FAILED, 0L),
                blockedCounts.getOrDefault(BlockedUserStatus.RESOLVED, 0L),
                blockedUserJpaRepository.findTop5ByStatusInOrderByBlockedAtDesc(List.of(BlockedUserStatus.BLOCKED, BlockedUserStatus.UNBLOCK_REQUESTED)),
                auditLogRepository.countAllowedSince(since24h),
                auditLogRepository.countDeniedAttemptsSince(since24h),
                eventCatCounts.getOrDefault("AUTHENTICATION_SUCCESS", 0L),
                eventCatCounts.getOrDefault("AUTHENTICATION_FAILURE", 0L),
                eventCatCounts.getOrDefault("SECURITY_DECISION", 0L),
                auditLogRepository.countAdminOverridesSince(since24h),
                auditLogRepository.countSecurityErrorsSince(since24h),
                auditLogRepository.countAfterHoursAccessSince(since24h),
                auditLogRepository.countDistinctIpsSince(since24h),
                auditLogRepository.avgRiskScoreSince(since24h),
                ztCounts.getOrDefault("ALLOW", 0L),
                ztTotal,
                ztCounts.getOrDefault("CHALLENGE", 0L),
                ztCounts.getOrDefault("BLOCK", 0L),
                ztCounts.getOrDefault("ESCALATE", 0L),
                auditLogRepository.countPolicyChangesSince(since24h),
                auditLogRepository.countIamChangesSince(since24h),
                auditLogRepository.findRecentThreatEvents(since24h).stream().limit(5).toList()
        );
    }

    private StatisticsDto buildStatistics(long policyTotal, long policyActive) {
        return new StatisticsDto(
                userRepository.count(),
                groupRepository.count(),
                roleRepository.count(),
                permissionRepository.count(),
                policyTotal,
                policyActive,
                userRepository.countByMfaEnabled(true),
                userRepository.countByMfaEnabled(false)
        );
    }

    private PolicyStatusDto buildPolicyStatus(long policyTotal, long policyActive) {
        List<Policy.PolicySource> aiSources = List.of(
                Policy.PolicySource.AI_GENERATED,
                Policy.PolicySource.AI_EVOLVED
        );

        // Policy source: 3 queries -> 1 GROUP BY
        Map<Policy.PolicySource, Long> sourceCounts = new EnumMap<>(Policy.PolicySource.class);
        for (Object[] row : policyRepository.countGroupBySource()) {
            sourceCounts.put((Policy.PolicySource) row[0], (Long) row[1]);
        }

        // AI approval: 3 queries -> 1 GROUP BY
        Map<Policy.ApprovalStatus, Long> approvalCounts = new EnumMap<>(Policy.ApprovalStatus.class);
        for (Object[] row : policyRepository.countAIApprovalGroupByStatus(aiSources)) {
            approvalCounts.put((Policy.ApprovalStatus) row[0], (Long) row[1]);
        }

        List<RecentPolicyDto> recentPolicies = policyRepository.findTop5ByOrderByCreatedAtDesc()
                .stream()
                .map(p -> new RecentPolicyDto(
                        p.getId(),
                        p.getName(),
                        p.getEffect().name(),
                        p.getSource().name(),
                        p.getApprovalStatus().name(),
                        p.getCreatedAt()
                ))
                .toList();

        return new PolicyStatusDto(
                policyTotal,
                policyActive,
                sourceCounts.getOrDefault(Policy.PolicySource.MANUAL, 0L),
                sourceCounts.getOrDefault(Policy.PolicySource.AI_GENERATED, 0L),
                sourceCounts.getOrDefault(Policy.PolicySource.AI_EVOLVED, 0L),
                approvalCounts.getOrDefault(Policy.ApprovalStatus.PENDING, 0L),
                approvalCounts.getOrDefault(Policy.ApprovalStatus.APPROVED, 0L),
                approvalCounts.getOrDefault(Policy.ApprovalStatus.REJECTED, 0L),
                policyRepository.calculateAverageConfidenceScoreForAIPolicies(),
                recentPolicies
        );
    }

    private List<AccessTrendDto> buildAccessTrends() {
        LocalDateTime since = LocalDateTime.now().minusHours(24);
        List<AuditLog> logs = auditLogRepository.findByCreatedAtAfter(since);

        Map<Integer, long[]> hourlyData = new TreeMap<>();
        for (int i = 0; i < 24; i++) {
            hourlyData.put(i, new long[]{0, 0});
        }

        for (AuditLog log : logs) {
            int hour = log.getTimestamp().getHour();
            long[] counts = hourlyData.get(hour);
            if ("DENY".equals(log.getDecision())) {
                counts[1]++;
            } else {
                counts[0]++;
            }
        }

        List<AccessTrendDto> trends = new ArrayList<>();
        for (Map.Entry<Integer, long[]> entry : hourlyData.entrySet()) {
            long[] counts = entry.getValue();
            trends.add(new AccessTrendDto(
                    String.format("%02d:00", entry.getKey()),
                    counts[0],
                    counts[1],
                    counts[0] + counts[1]
            ));
        }

        return trends;
    }

    private List<RiskIndicatorDto> analyzeRiskIndicators() {
        List<RiskIndicatorDto> risks = new ArrayList<>();

        long mfaDisabledAdmins = userRepository.findAdminsWithMfaDisabled().size();
        if (mfaDisabledAdmins > 0) {
            risks.add(new RiskIndicatorDto(
                    "CRITICAL",
                    "Admin accounts without MFA detected",
                    mfaDisabledAdmins + " admin accounts do not have MFA enabled, posing a high risk of account compromise.",
                    "/admin/users"
            ));
        }

        List<Policy.PolicySource> aiSources = List.of(
                Policy.PolicySource.AI_GENERATED,
                Policy.PolicySource.AI_EVOLVED
        );
        long pendingPolicies = policyRepository.countBySourceInAndApprovalStatus(aiSources, Policy.ApprovalStatus.PENDING);
        if (pendingPolicies > 0) {
            risks.add(new RiskIndicatorDto(
                    "WARNING",
                    "AI policies pending approval",
                    pendingPolicies + " AI-generated policies are awaiting approval. Please review and approve or reject.",
                    "/admin/policies"
            ));
        }

        LocalDateTime last24Hours = LocalDateTime.now().minusHours(24);
        long deniedAttempts = auditLogRepository.countDeniedAttemptsSince(last24Hours);
        if (deniedAttempts >= 10) {
            risks.add(new RiskIndicatorDto(
                    "WARNING",
                    "High number of access denials in last 24 hours",
                    deniedAttempts + " access attempts were denied in the last 24 hours. This may indicate abnormal access attempts.",
                    "/admin/studio"
            ));
        }

        boolean hasRoleHierarchy = roleHierarchyRepository.existsByIsActiveTrue();
        if (!hasRoleHierarchy) {
            risks.add(new RiskIndicatorDto(
                    "WARNING",
                    "Role hierarchy not defined",
                    "No role hierarchy has been defined. Set up inheritance relationships between roles to streamline permission management.",
                    "/admin/role-hierarchies"
            ));
        }

        return risks;
    }
}
