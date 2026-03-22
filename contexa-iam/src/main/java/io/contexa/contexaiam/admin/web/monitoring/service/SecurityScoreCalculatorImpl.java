package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexaiam.admin.web.monitoring.dto.SecurityScoreDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.RoleHierarchyRepository;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
public class SecurityScoreCalculatorImpl implements SecurityScoreCalculator {

    private final UserRepository userRepository;
    private final PolicyRepository policyRepository;
    private final RoleHierarchyRepository roleHierarchyRepository;
    private final AuditLogRepository auditLogRepository;

    @Override
    public SecurityScoreDto calculate() {
        List<SecurityScoreDto.ScoreFactor> factors = new ArrayList<>();
        double totalScore = 0.0;

        int adminMfaScore = calculateAdminMfaScore();
        factors.add(new SecurityScoreDto.ScoreFactor(
                "Admin MFA Activation Rate",
                adminMfaScore,
                0.35,
                "Admin accounts with MFA enabled"
        ));
        totalScore += adminMfaScore * 0.35;

        int userMfaScore = calculateUserMfaScore();
        factors.add(new SecurityScoreDto.ScoreFactor(
                "User MFA Activation Rate",
                userMfaScore,
                0.20,
                "General user accounts with MFA enabled"
        ));
        totalScore += userMfaScore * 0.20;

        int roleHierarchyScore = calculateRoleHierarchyScore();
        factors.add(new SecurityScoreDto.ScoreFactor(
                "Role Hierarchy Status",
                roleHierarchyScore,
                0.15,
                "Role hierarchy definition status"
        ));
        totalScore += roleHierarchyScore * 0.15;

        int policyApprovalScore = calculatePolicyApprovalScore();
        factors.add(new SecurityScoreDto.ScoreFactor(
                "AI Policy Approval Rate",
                policyApprovalScore,
                0.15,
                "AI-generated policy approval rate"
        ));
        totalScore += policyApprovalScore * 0.15;

        int accessDenyScore = calculateAccessDenyScore();
        factors.add(new SecurityScoreDto.ScoreFactor(
                "Access Deny Rate (Inverted)",
                accessDenyScore,
                0.15,
                "Low deny rate indicates normal access patterns"
        ));
        totalScore += accessDenyScore * 0.15;

        int finalScore = (int) Math.round(totalScore);
        String summary = generateSummary(finalScore);

        return new SecurityScoreDto(finalScore, summary, factors);
    }

    private int calculateAdminMfaScore() {
        long adminCount = userRepository.countByRoles("ADMIN");
        if (adminCount == 0) {
            return 100;
        }
        long mfaEnabledAdminCount = adminCount - userRepository.countByMfaEnabledAndRoles(false, "ADMIN");
        return (int) ((mfaEnabledAdminCount * 100) / adminCount);
    }

    private int calculateUserMfaScore() {
        long totalUsers = userRepository.count();
        if (totalUsers == 0) {
            return 100;
        }
        long mfaEnabledUsers = userRepository.countByMfaEnabled(true);
        return (int) ((mfaEnabledUsers * 100) / totalUsers);
    }

    private int calculateRoleHierarchyScore() {
        boolean hasRoleHierarchy = roleHierarchyRepository.existsByIsActiveTrue();
        return hasRoleHierarchy ? 100 : 0;
    }

    private int calculatePolicyApprovalScore() {
        List<Policy.PolicySource> aiSources = List.of(
                Policy.PolicySource.AI_GENERATED,
                Policy.PolicySource.AI_EVOLVED
        );

        long totalAiPolicies = policyRepository.countBySourceIn(aiSources);
        if (totalAiPolicies == 0) {
            return 100;
        }

        long approvedPolicies = policyRepository.countBySourceInAndApprovalStatus(
                aiSources, Policy.ApprovalStatus.APPROVED);
        long notRequiredPolicies = policyRepository.countBySourceInAndApprovalStatus(
                aiSources, Policy.ApprovalStatus.NOT_REQUIRED);

        long processedPolicies = approvedPolicies + notRequiredPolicies;
        return (int) ((processedPolicies * 100) / totalAiPolicies);
    }

    private int calculateAccessDenyScore() {
        LocalDateTime last24Hours = LocalDateTime.now().minusHours(24);
        List<io.contexa.contexacommon.entity.AuditLog> recentLogs =
                auditLogRepository.findByCreatedAtAfter(last24Hours);

        if (recentLogs.isEmpty()) {
            return 100;
        }

        long denyCount = recentLogs.stream()
                .filter(log -> "DENY".equals(log.getDecision()))
                .count();

        double denyRate = (double) denyCount / recentLogs.size();

        if (denyRate <= 0.01) {
            return 100;
        } else if (denyRate <= 0.05) {
            return 80;
        } else if (denyRate <= 0.10) {
            return 60;
        } else if (denyRate <= 0.20) {
            return 40;
        } else {
            return 20;
        }
    }

    private String generateSummary(int score) {
        if (score >= 90) {
            return "Excellent security posture. All critical controls are properly configured.";
        } else if (score >= 80) {
            return "Good security status. Minor improvements recommended.";
        } else if (score >= 60) {
            return "Security improvements needed. Review the factors below.";
        } else if (score >= 40) {
            return "Security concerns detected. Immediate attention required.";
        } else {
            return "Critical security issues. Urgent action required.";
        }
    }
}
