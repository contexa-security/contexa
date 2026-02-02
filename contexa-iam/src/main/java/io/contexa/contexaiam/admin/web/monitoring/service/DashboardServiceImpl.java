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
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
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

    @Override
    @Transactional(readOnly = true)
    public DashboardDto getDashboardData() {
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();

        return new DashboardDto(
                buildStatistics(),
                userContextService.getRecentActivities(currentUsername),
                analyzeRiskIndicators(),
                securityScoreCalculator.calculate(),
                permissionMatrixService.getPermissionMatrix(null),
                buildPolicyStatus(),
                buildAccessTrends()
        );
    }

    private StatisticsDto buildStatistics() {
        return new StatisticsDto(
                userRepository.count(),
                groupRepository.count(),
                roleRepository.count(),
                permissionRepository.count(),
                policyRepository.count(),
                policyRepository.countByIsActiveTrue(),
                userRepository.countByMfaEnabled(true),
                userRepository.countByMfaEnabled(false)
        );
    }

    private PolicyStatusDto buildPolicyStatus() {
        List<Policy.PolicySource> aiSources = List.of(
                Policy.PolicySource.AI_GENERATED,
                Policy.PolicySource.AI_EVOLVED
        );

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
                policyRepository.count(),
                policyRepository.countByIsActiveTrue(),
                policyRepository.countBySource(Policy.PolicySource.MANUAL),
                policyRepository.countBySource(Policy.PolicySource.AI_GENERATED),
                policyRepository.countBySource(Policy.PolicySource.AI_EVOLVED),
                policyRepository.countBySourceInAndApprovalStatus(aiSources, Policy.ApprovalStatus.PENDING),
                policyRepository.countBySourceInAndApprovalStatus(aiSources, Policy.ApprovalStatus.APPROVED),
                policyRepository.countBySourceInAndApprovalStatus(aiSources, Policy.ApprovalStatus.REJECTED),
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
                    "MFA 미사용 관리자 계정 발견",
                    mfaDisabledAdmins + "명의 관리자 계정에 2단계 인증(MFA)이 설정되지 않아 탈취 위험이 높습니다.",
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
                    "승인 대기 중인 AI 정책",
                    pendingPolicies + "개의 AI 생성 정책이 승인을 기다리고 있습니다. 검토 후 승인 또는 거부해주세요.",
                    "/admin/policies"
            ));
        }

        LocalDateTime last24Hours = LocalDateTime.now().minusHours(24);
        long deniedAttempts = auditLogRepository.countDeniedAttemptsSince(last24Hours);
        if (deniedAttempts >= 10) {
            risks.add(new RiskIndicatorDto(
                    "WARNING",
                    "최근 24시간 접근 거부 다발",
                    "최근 24시간 동안 " + deniedAttempts + "건의 접근이 거부되었습니다. 비정상적인 접근 시도일 수 있습니다.",
                    "/admin/studio"
            ));
        }

        boolean hasRoleHierarchy = roleHierarchyRepository.findByIsActiveTrue().isPresent();
        if (!hasRoleHierarchy) {
            risks.add(new RiskIndicatorDto(
                    "WARNING",
                    "역할 계층 미정의",
                    "역할 계층이 정의되지 않았습니다. 역할 간 상속 관계를 설정하여 권한 관리를 효율화하세요.",
                    "/admin/role-hierarchies"
            ));
        }

        return risks;
    }
}
