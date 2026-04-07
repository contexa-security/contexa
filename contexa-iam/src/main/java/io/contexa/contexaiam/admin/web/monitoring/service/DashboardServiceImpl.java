package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexaiam.admin.web.monitoring.dto.DashboardDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.PolicyHealthDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.RiskIndicatorDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.StatisticsDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.PolicyStatusDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.RecentPolicyDto;
import io.contexa.contexaiam.admin.web.monitoring.dto.AccessTrendDto;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
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
    private final PolicyValidationService policyValidationService;
    private final PolicyCombiningProperties policyCombiningProperties;

    @Override
    @Transactional(readOnly = true)
    public DashboardDto getDashboardData() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = (authentication != null) ? authentication.getName() : "SYSTEM";
        LocalDateTime since24h = LocalDateTime.now().minusHours(24);

        // ManagedResource: 3 queries -> 1 GROUP BY
        Map<ManagedResource.Status, Long> resourceCounts = new EnumMap<>(ManagedResource.Status.class);
        long resourceTotal = 0;
        for (Object[] row : managedResourceRepository.countGroupByStatus()) {
            if (row.length >= 2 && row[0] instanceof ManagedResource.Status status && row[1] instanceof Number count) {
                resourceCounts.put(status, count.longValue());
                resourceTotal += count.longValue();
            }
        }

        // BlockedUser: 5 queries -> 1 GROUP BY
        Map<BlockedUserStatus, Long> blockedCounts = new EnumMap<>(BlockedUserStatus.class);
        for (Object[] row : blockedUserJpaRepository.countGroupByStatus()) {
            if (row.length >= 2 && row[0] instanceof BlockedUserStatus status && row[1] instanceof Number count) {
                blockedCounts.put(status, count.longValue());
            }
        }

        // AuditLog EventCategory: 3 queries -> 1 GROUP BY
        Map<String, Long> eventCatCounts = new HashMap<>();
        for (Object[] row : auditLogRepository.countByEventCategoriesGrouped(since24h,
                List.of("AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILURE", "SECURITY_DECISION"))) {
            if (row.length >= 2 && row[0] instanceof String category && row[1] instanceof Number count) {
                eventCatCounts.put(category, count.longValue());
            }
        }

        // ZeroTrust Decision: 5 queries -> 1 GROUP BY
        Map<String, Long> ztCounts = new HashMap<>();
        long ztTotal = 0;
        for (Object[] row : auditLogRepository.countZeroTrustGroupByDecision(since24h)) {
            if (row.length >= 2 && row[0] instanceof String decision && row[1] instanceof Number count) {
                ztCounts.put(decision, count.longValue());
                ztTotal += count.longValue();
            }
        }

        // Policy counts: computed once, shared between buildStatistics and buildPolicyStatus
        long policyTotal = policyRepository.count();
        long policyActive = policyRepository.countByIsActiveTrue();
        long denyCount24h = auditLogRepository.countDeniedAttemptsSince(since24h);

        PolicyHealthDto policyHealth = buildPolicyHealth();

        return new DashboardDto(
                buildStatistics(policyTotal, policyActive),
                userContextService.getRecentActivities(currentUsername),
                analyzeRiskIndicators(denyCount24h),
                securityScoreCalculator.calculate(),
                permissionMatrixService.getPermissionMatrix(null),
                buildPolicyStatus(policyTotal, policyActive),
                policyHealth,
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
                denyCount24h,
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
            if (row.length >= 2 && row[0] instanceof Policy.PolicySource source && row[1] instanceof Number count) {
                sourceCounts.put(source, count.longValue());
            }
        }

        // All approval status: 1 GROUP BY
        Map<Policy.ApprovalStatus, Long> approvalCounts = new EnumMap<>(Policy.ApprovalStatus.class);
        for (Object[] row : policyRepository.countGroupByApprovalStatus()) {
            if (row.length >= 2 && row[0] instanceof Policy.ApprovalStatus status && row[1] instanceof Number count) {
                approvalCounts.put(status, count.longValue());
            }
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
                policyTotal - policyActive,
                sourceCounts.getOrDefault(Policy.PolicySource.MANUAL, 0L),
                sourceCounts.getOrDefault(Policy.PolicySource.AI_GENERATED, 0L),
                sourceCounts.getOrDefault(Policy.PolicySource.AI_EVOLVED, 0L),
                sourceCounts.getOrDefault(Policy.PolicySource.IMPORTED, 0L),
                approvalCounts.getOrDefault(Policy.ApprovalStatus.PENDING, 0L),
                approvalCounts.getOrDefault(Policy.ApprovalStatus.APPROVED, 0L),
                approvalCounts.getOrDefault(Policy.ApprovalStatus.REJECTED, 0L),
                approvalCounts.getOrDefault(Policy.ApprovalStatus.NOT_REQUIRED, 0L),
                policyRepository.calculateAverageConfidenceScoreForAIPolicies(),
                recentPolicies
        );
    }

    private PolicyHealthDto buildPolicyHealth() {
        try {
            FullValidationReport report = policyValidationService.validateAll();
            return new PolicyHealthDto(
                    report.healthStatus(),
                    report.conflicts().size(),
                    report.duplicates().size(),
                    policyCombiningProperties.getCombiningAlgorithm().name());
        } catch (Exception e) {
            return new PolicyHealthDto("UNKNOWN", 0, 0,
                    policyCombiningProperties.getCombiningAlgorithm().name());
        }
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

    private List<RiskIndicatorDto> analyzeRiskIndicators(long denyCount24h) {
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

        if (denyCount24h >= 10) {
            risks.add(new RiskIndicatorDto(
                    "WARNING",
                    "High number of access denials in last 24 hours",
                    denyCount24h + " access attempts were denied in the last 24 hours. This may indicate abnormal access attempts.",
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
