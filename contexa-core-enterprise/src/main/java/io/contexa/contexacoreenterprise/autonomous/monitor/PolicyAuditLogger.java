package io.contexa.contexacoreenterprise.autonomous.monitor;

import io.contexa.contexacoreenterprise.repository.SynthesisPolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class PolicyAuditLogger {
    
    private final SynthesisPolicyRepository synthesisPolicyRepository;
    
    
    private final Map<String, AuditLogEntry> auditLogs = new ConcurrentHashMap<>();
    
    
    private final Map<String, ComplianceCheckpoint> complianceCheckpoints = new ConcurrentHashMap<>();
    
    
    public static class AuditLogEntry {
        private String auditId;
        private LocalDateTime timestamp;
        private String eventType;
        private String actor;
        private String targetEntity;
        private String action;
        private Map<String, Object> details;
        private String outcome;
        private String ipAddress;
        private String userAgent;
        
        public AuditLogEntry(String eventType, String actor, String targetEntity, String action) {
            this.auditId = UUID.randomUUID().toString();
            this.timestamp = LocalDateTime.now();
            this.eventType = eventType;
            this.actor = actor;
            this.targetEntity = targetEntity;
            this.action = action;
            this.details = new HashMap<>();
        }
        
        public void addDetail(String key, Object value) {
            details.put(key, value);
        }
        
        public void setOutcome(String outcome) {
            this.outcome = outcome;
        }
        
        public void setContextInfo(String ipAddress, String userAgent) {
            this.ipAddress = ipAddress;
            this.userAgent = userAgent;
        }
        
        @Override
        public String toString() {
            return String.format("[%s] %s: %s performed %s on %s - %s",
                timestamp.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                eventType, actor, action, targetEntity, outcome);
        }
    }
    
    
    public static class ComplianceCheckpoint {
        private String checkpointId;
        private LocalDateTime timestamp;
        private String complianceType;
        private boolean compliant;
        private List<String> violations;
        private Map<String, Object> evidence;
        private String remediationRequired;
        
        public ComplianceCheckpoint(String complianceType) {
            this.checkpointId = UUID.randomUUID().toString();
            this.timestamp = LocalDateTime.now();
            this.complianceType = complianceType;
            this.compliant = true;
            this.violations = new ArrayList<>();
            this.evidence = new HashMap<>();
        }
        
        public void addViolation(String violation) {
            this.compliant = false;
            this.violations.add(violation);
        }
        
        public void addEvidence(String key, Object value) {
            this.evidence.put(key, value);
        }
        
        public void setRemediationRequired(String remediation) {
            this.remediationRequired = remediation;
        }
        
        public boolean isCompliant() {
            return compliant;
        }
    }
    
    
    public void logPolicyCreation(Long proposalId, String createdBy, Map<String, Object> context) {
        AuditLogEntry entry = new AuditLogEntry(
            "POLICY_CREATION",
            createdBy,
            "Proposal#" + proposalId,
            "CREATE"
        );
        
        entry.addDetail("proposalId", proposalId);
        entry.addDetail("timestamp", LocalDateTime.now());
        entry.addDetail("context", context);
        entry.setOutcome("SUCCESS");
        
        String auditId = entry.auditId;
        auditLogs.put(auditId, entry);
        
        log.info("Audit Log - Policy Creation: {}", entry);
        
        
        checkCreationCompliance(proposalId, createdBy);
    }
    
    
    public void logPolicyApproval(Long proposalId, String approvedBy, String approvalLevel, Map<String, Object> context) {
        AuditLogEntry entry = new AuditLogEntry(
            "POLICY_APPROVAL",
            approvedBy,
            "Proposal#" + proposalId,
            "APPROVE"
        );
        
        entry.addDetail("proposalId", proposalId);
        entry.addDetail("approvalLevel", approvalLevel);
        entry.addDetail("timestamp", LocalDateTime.now());
        entry.addDetail("context", context);
        entry.setOutcome("APPROVED");
        
        String auditId = entry.auditId;
        auditLogs.put(auditId, entry);
        
        log.info("Audit Log - Policy Approval: {}", entry);
        
        
        checkApprovalCompliance(proposalId, approvedBy, approvalLevel);
    }
    
    
    public void logPolicyRejection(Long proposalId, String rejectedBy, String reason, Map<String, Object> context) {
        AuditLogEntry entry = new AuditLogEntry(
            "POLICY_REJECTION",
            rejectedBy,
            "Proposal#" + proposalId,
            "REJECT"
        );
        
        entry.addDetail("proposalId", proposalId);
        entry.addDetail("reason", reason);
        entry.addDetail("timestamp", LocalDateTime.now());
        entry.addDetail("context", context);
        entry.setOutcome("REJECTED");
        
        String auditId = entry.auditId;
        auditLogs.put(auditId, entry);
        
        log.info("Audit Log - Policy Rejection: {}", entry);
    }
    
    
    public void logPolicyActivation(Long policyId, String activatedBy, Map<String, Object> context) {
        AuditLogEntry entry = new AuditLogEntry(
            "POLICY_ACTIVATION",
            activatedBy,
            "Policy#" + policyId,
            "ACTIVATE"
        );
        
        entry.addDetail("policyId", policyId);
        entry.addDetail("timestamp", LocalDateTime.now());
        entry.addDetail("context", context);
        entry.setOutcome("ACTIVATED");
        
        String auditId = entry.auditId;
        auditLogs.put(auditId, entry);
        
        log.info("Audit Log - Policy Activation: {}", entry);
        
        
        checkActivationCompliance(policyId, activatedBy);
    }
    
    
    public void logPolicyDeactivation(Long policyId, String deactivatedBy, String reason, Map<String, Object> context) {
        AuditLogEntry entry = new AuditLogEntry(
            "POLICY_DEACTIVATION",
            deactivatedBy,
            "Policy#" + policyId,
            "DEACTIVATE"
        );
        
        entry.addDetail("policyId", policyId);
        entry.addDetail("reason", reason);
        entry.addDetail("timestamp", LocalDateTime.now());
        entry.addDetail("context", context);
        entry.setOutcome("DEACTIVATED");
        
        String auditId = entry.auditId;
        auditLogs.put(auditId, entry);
        
        log.info("Audit Log - Policy Deactivation: {}", entry);
    }
    
    
    public void logPolicyRollback(Long policyId, int fromVersion, int toVersion, String rolledBackBy, String reason) {
        AuditLogEntry entry = new AuditLogEntry(
            "POLICY_ROLLBACK",
            rolledBackBy,
            "Policy#" + policyId,
            "ROLLBACK"
        );
        
        entry.addDetail("policyId", policyId);
        entry.addDetail("fromVersion", fromVersion);
        entry.addDetail("toVersion", toVersion);
        entry.addDetail("reason", reason);
        entry.addDetail("timestamp", LocalDateTime.now());
        entry.setOutcome("ROLLED_BACK");
        
        String auditId = entry.auditId;
        auditLogs.put(auditId, entry);
        
        log.info("Audit Log - Policy Rollback: {}", entry);
    }
    
    
    private void checkCreationCompliance(Long proposalId, String createdBy) {
        ComplianceCheckpoint checkpoint = new ComplianceCheckpoint("CREATION_COMPLIANCE");
        
        
        if (!hasCreationPermission(createdBy)) {
            checkpoint.addViolation("User lacks policy creation permission");
        }
        
        
        if (!validatePolicyNamingConvention(proposalId)) {
            checkpoint.addViolation("Policy naming convention violated");
        }
        
        
        if (!validatePolicyContent(proposalId)) {
            checkpoint.addViolation("Policy content validation failed");
        }
        
        checkpoint.addEvidence("proposalId", proposalId);
        checkpoint.addEvidence("createdBy", createdBy);
        checkpoint.addEvidence("timestamp", LocalDateTime.now());
        
        if (!checkpoint.isCompliant()) {
            checkpoint.setRemediationRequired("Review and correct policy creation violations");
            log.warn("Compliance violation detected in policy creation: {}", checkpoint.violations);
        }
        
        complianceCheckpoints.put(checkpoint.checkpointId, checkpoint);
    }
    
    
    private void checkApprovalCompliance(Long proposalId, String approvedBy, String approvalLevel) {
        ComplianceCheckpoint checkpoint = new ComplianceCheckpoint("APPROVAL_COMPLIANCE");
        
        
        if (!hasApprovalPermission(approvedBy, approvalLevel)) {
            checkpoint.addViolation("User lacks appropriate approval permission for level: " + approvalLevel);
        }
        
        
        if (hasConflictOfInterest(proposalId, approvedBy)) {
            checkpoint.addViolation("Conflict of interest detected - approver created the proposal");
        }
        
        
        if (!withinApprovalTimeline(proposalId)) {
            checkpoint.addViolation("Approval exceeded timeline requirements");
        }
        
        checkpoint.addEvidence("proposalId", proposalId);
        checkpoint.addEvidence("approvedBy", approvedBy);
        checkpoint.addEvidence("approvalLevel", approvalLevel);
        checkpoint.addEvidence("timestamp", LocalDateTime.now());
        
        if (!checkpoint.isCompliant()) {
            checkpoint.setRemediationRequired("Review approval process violations");
            log.warn("Compliance violation detected in approval process: {}", checkpoint.violations);
        }
        
        complianceCheckpoints.put(checkpoint.checkpointId, checkpoint);
    }
    
    
    private void checkActivationCompliance(Long policyId, String activatedBy) {
        ComplianceCheckpoint checkpoint = new ComplianceCheckpoint("ACTIVATION_COMPLIANCE");
        
        
        if (!hasActivationPermission(activatedBy)) {
            checkpoint.addViolation("User lacks policy activation permission");
        }
        
        
        if (!hasPassedRequiredTests(policyId)) {
            checkpoint.addViolation("Policy has not passed required tests");
        }
        
        
        if (!hasRequiredDocumentation(policyId)) {
            checkpoint.addViolation("Policy lacks required documentation");
        }
        
        checkpoint.addEvidence("policyId", policyId);
        checkpoint.addEvidence("activatedBy", activatedBy);
        checkpoint.addEvidence("timestamp", LocalDateTime.now());
        
        if (!checkpoint.isCompliant()) {
            checkpoint.setRemediationRequired("Complete pre-activation requirements");
            log.warn("Compliance violation detected in policy activation: {}", checkpoint.violations);
        }
        
        complianceCheckpoints.put(checkpoint.checkpointId, checkpoint);
    }
    
    

    private static final String ROLE_POLICY_CREATOR = "ROLE_POLICY_CREATOR";
    private static final String ROLE_POLICY_APPROVER = "ROLE_POLICY_APPROVER";
    private static final String ROLE_POLICY_ADMIN = "ROLE_POLICY_ADMIN";
    private static final String ROLE_SECURITY_ADMIN = "ROLE_SECURITY_ADMIN";

    
    private boolean hasCreationPermission(String user) {
        if (user == null || user.isEmpty()) {
            log.warn("[Zero Trust] 정책 생성 권한 검증 실패: 사용자 정보 없음");
            return false;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("[Zero Trust] 정책 생성 권한 검증 실패: 인증되지 않은 사용자");
            return false;
        }

        
        if (!user.equals(authentication.getName())) {
            return false;
        }

        
        boolean hasPermission = hasAnyRole(authentication, ROLE_POLICY_CREATOR, ROLE_POLICY_ADMIN, ROLE_SECURITY_ADMIN);
        if (!hasPermission) {
            log.warn("[Zero Trust] 정책 생성 권한 부족: user={}", user);
        }
        return hasPermission;
    }

    
    private boolean hasApprovalPermission(String user, String level) {
        if (user == null || user.isEmpty() || level == null) {
            log.warn("[Zero Trust] 정책 승인 권한 검증 실패: 필수 정보 누락");
            return false;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("[Zero Trust] 정책 승인 권한 검증 실패: 인증되지 않은 사용자");
            return false;
        }

        
        if (!user.equals(authentication.getName())) {
            log.warn("[Zero Trust] 정책 승인 권한 검증 실패: 사용자 불일치");
            return false;
        }

        
        String requiredRole = switch (level.toUpperCase()) {
            case "L1", "LEVEL1", "BASIC" -> ROLE_POLICY_APPROVER;
            case "L2", "LEVEL2", "ADVANCED" -> ROLE_POLICY_ADMIN;
            case "L3", "LEVEL3", "CRITICAL" -> ROLE_SECURITY_ADMIN;
            default -> ROLE_POLICY_ADMIN;
        };

        boolean hasPermission = hasRole(authentication, requiredRole) ||
                                hasRole(authentication, ROLE_SECURITY_ADMIN); 

        if (!hasPermission) {
            log.warn("[Zero Trust] 정책 승인 권한 부족: level={}, requiredRole={}, user={}",
                    level, requiredRole, user);
        }
        return hasPermission;
    }

    
    private boolean hasActivationPermission(String user) {
        if (user == null || user.isEmpty()) {
            log.warn("[Zero Trust] 정책 활성화 권한 검증 실패: 사용자 정보 없음");
            return false;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("[Zero Trust] 정책 활성화 권한 검증 실패: 인증되지 않은 사용자");
            return false;
        }

        
        if (!user.equals(authentication.getName())) {
            log.warn("[Zero Trust] 정책 활성화 권한 검증 실패: 사용자 불일치");
            return false;
        }

        boolean hasPermission = hasAnyRole(authentication, ROLE_POLICY_ADMIN, ROLE_SECURITY_ADMIN);
        if (!hasPermission) {
        }
        return hasPermission;
    }

    
    private boolean hasRole(Authentication authentication, String role) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority -> authority.equals(role));
    }

    
    private boolean hasAnyRole(Authentication authentication, String... roles) {
        Set<String> requiredRoles = Set.of(roles);
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(requiredRoles::contains);
    }

    
    private boolean hasConflictOfInterest(Long proposalId, String approver) {
        if (proposalId == null || approver == null) {
            return false;
        }

        
        Optional<String> creatorOpt = synthesisPolicyRepository.findById(proposalId)
                .map(policy -> policy.getCreatedBy())
                .filter(creator -> creator != null);

        if (creatorOpt.isEmpty()) {
            log.debug("정책 제안 #{} 의 생성자를 찾을 수 없음", proposalId);
            return false;
        }

        String creator = creatorOpt.get();
        boolean conflict = creator.equals(approver);

        if (conflict) {
        }

        return conflict;
    }

    
    private boolean withinApprovalTimeline(Long proposalId) {
        
        return true;
    }

    
    private boolean validatePolicyNamingConvention(Long proposalId) {
        
        return true;
    }

    
    private boolean validatePolicyContent(Long proposalId) {
        
        return true;
    }

    
    private boolean hasPassedRequiredTests(Long policyId) {
        
        return true;
    }

    
    private boolean hasRequiredDocumentation(Long policyId) {
        
        return true;
    }
    
    
    public ComplianceReport generateComplianceReport(LocalDateTime startDate, LocalDateTime endDate) {
        ComplianceReport report = new ComplianceReport();
        report.setReportId(UUID.randomUUID().toString());
        report.setGeneratedAt(LocalDateTime.now());
        report.setStartDate(startDate);
        report.setEndDate(endDate);
        
        
        List<AuditLogEntry> periodLogs = auditLogs.values().stream()
            .filter(log -> log.timestamp.isAfter(startDate) && log.timestamp.isBefore(endDate))
            .collect(Collectors.toList());
        
        report.setTotalEvents(periodLogs.size());
        
        
        Map<String, Long> eventTypeCounts = periodLogs.stream()
            .collect(Collectors.groupingBy(
                log -> log.eventType,
                Collectors.counting()
            ));
        report.setEventTypeCounts(eventTypeCounts);
        
        
        List<ComplianceCheckpoint> periodCheckpoints = complianceCheckpoints.values().stream()
            .filter(cp -> cp.timestamp.isAfter(startDate) && cp.timestamp.isBefore(endDate))
            .collect(Collectors.toList());
        
        long totalViolations = periodCheckpoints.stream()
            .filter(cp -> !cp.isCompliant())
            .count();
        report.setTotalViolations(totalViolations);
        
        
        Map<String, List<String>> violationsByType = periodCheckpoints.stream()
            .filter(cp -> !cp.isCompliant())
            .collect(Collectors.groupingBy(
                cp -> cp.complianceType,
                Collectors.flatMapping(cp -> cp.violations.stream(), Collectors.toList())
            ));
        report.setViolationsByType(violationsByType);
        
        
        double complianceScore = periodCheckpoints.isEmpty() ? 100.0 :
            (double)(periodCheckpoints.size() - totalViolations) / periodCheckpoints.size() * 100;
        report.setComplianceScore(complianceScore);
        
        
        List<String> recommendations = generateRecommendations(violationsByType);
        report.setRecommendations(recommendations);
        
        log.info("Compliance Report Generated: {} events, {} violations, {:.2f}% compliance score",
            report.getTotalEvents(), report.getTotalViolations(), report.getComplianceScore());
        
        return report;
    }
    
    
    private List<String> generateRecommendations(Map<String, List<String>> violationsByType) {
        List<String> recommendations = new ArrayList<>();
        
        if (violationsByType.containsKey("CREATION_COMPLIANCE")) {
            recommendations.add("Strengthen policy creation validation and permission checks");
        }
        
        if (violationsByType.containsKey("APPROVAL_COMPLIANCE")) {
            recommendations.add("Review approval workflow and implement stricter conflict of interest checks");
        }
        
        if (violationsByType.containsKey("ACTIVATION_COMPLIANCE")) {
            recommendations.add("Ensure all policies pass required tests before activation");
        }
        
        if (violationsByType.size() > 3) {
            recommendations.add("Consider comprehensive compliance training for policy administrators");
        }
        
        return recommendations;
    }
    
    
    public static class ComplianceReport {
        private String reportId;
        private LocalDateTime generatedAt;
        private LocalDateTime startDate;
        private LocalDateTime endDate;
        private long totalEvents;
        private Map<String, Long> eventTypeCounts;
        private long totalViolations;
        private Map<String, List<String>> violationsByType;
        private double complianceScore;
        private List<String> recommendations;
        
        
        public String getReportId() { return reportId; }
        public void setReportId(String reportId) { this.reportId = reportId; }
        
        public LocalDateTime getGeneratedAt() { return generatedAt; }
        public void setGeneratedAt(LocalDateTime generatedAt) { this.generatedAt = generatedAt; }
        
        public LocalDateTime getStartDate() { return startDate; }
        public void setStartDate(LocalDateTime startDate) { this.startDate = startDate; }
        
        public LocalDateTime getEndDate() { return endDate; }
        public void setEndDate(LocalDateTime endDate) { this.endDate = endDate; }
        
        public long getTotalEvents() { return totalEvents; }
        public void setTotalEvents(long totalEvents) { this.totalEvents = totalEvents; }
        
        public Map<String, Long> getEventTypeCounts() { return eventTypeCounts; }
        public void setEventTypeCounts(Map<String, Long> eventTypeCounts) { this.eventTypeCounts = eventTypeCounts; }
        
        public long getTotalViolations() { return totalViolations; }
        public void setTotalViolations(long totalViolations) { this.totalViolations = totalViolations; }
        
        public Map<String, List<String>> getViolationsByType() { return violationsByType; }
        public void setViolationsByType(Map<String, List<String>> violationsByType) { this.violationsByType = violationsByType; }
        
        public double getComplianceScore() { return complianceScore; }
        public void setComplianceScore(double complianceScore) { this.complianceScore = complianceScore; }
        
        public List<String> getRecommendations() { return recommendations; }
        public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }
    }
    
    

    public void performDailyComplianceCheck() {
        log.info("Starting daily compliance check...");
        
        LocalDateTime yesterday = LocalDateTime.now().minusDays(1);
        LocalDateTime today = LocalDateTime.now();
        
        ComplianceReport dailyReport = generateComplianceReport(yesterday, today);
        
        if (dailyReport.getComplianceScore() < 80.0) {
            log.warn("Daily compliance score below threshold: {:.2f}%", dailyReport.getComplianceScore());
            
        }
        
        
        cleanupOldLogs();
    }
    
    
    private void cleanupOldLogs() {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(30);
        
        auditLogs.entrySet().removeIf(entry -> 
            entry.getValue().timestamp.isBefore(cutoffDate)
        );
        
        complianceCheckpoints.entrySet().removeIf(entry ->
            entry.getValue().timestamp.isBefore(cutoffDate)
        );
        
        log.info("Cleaned up logs older than {}", cutoffDate);
    }
    
    
    public List<AuditLogEntry> searchAuditLogs(String eventType, String actor, 
                                               LocalDateTime startDate, LocalDateTime endDate) {
        return auditLogs.values().stream()
            .filter(log -> eventType == null || log.eventType.equals(eventType))
            .filter(log -> actor == null || log.actor.equals(actor))
            .filter(log -> startDate == null || log.timestamp.isAfter(startDate))
            .filter(log -> endDate == null || log.timestamp.isBefore(endDate))
            .sorted(Comparator.comparing(log -> log.timestamp))
            .collect(Collectors.toList());
    }
    
    
    public List<ComplianceCheckpoint> searchComplianceCheckpoints(String complianceType, 
                                                                  boolean violationsOnly) {
        return complianceCheckpoints.values().stream()
            .filter(cp -> complianceType == null || cp.complianceType.equals(complianceType))
            .filter(cp -> !violationsOnly || !cp.isCompliant())
            .sorted(Comparator.comparing(cp -> cp.timestamp))
            .collect(Collectors.toList());
    }
}