package io.contexa.contexacore.autonomous.monitor;

import io.contexa.contexacore.autonomous.governance.SynthesisPolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 정책 감사 로거
 * 모든 정책 변경사항과 승인 프로세스를 추적하고 컴플라이언스 보고서를 생성
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PolicyAuditLogger {
    
    private final SynthesisPolicyRepository synthesisPolicyRepository;
    
    // 감사 로그 저장소
    private final Map<String, AuditLogEntry> auditLogs = new ConcurrentHashMap<>();
    
    // 컴플라이언스 체크포인트
    private final Map<String, ComplianceCheckpoint> complianceCheckpoints = new ConcurrentHashMap<>();
    
    /**
     * 감사 로그 엔트리
     */
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
    
    /**
     * 컴플라이언스 체크포인트
     */
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
    
    /**
     * 정책 생성 감사 로그
     */
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
        
        // 컴플라이언스 체크
        checkCreationCompliance(proposalId, createdBy);
    }
    
    /**
     * 정책 승인 감사 로그
     */
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
        
        // 승인 프로세스 컴플라이언스 체크
        checkApprovalCompliance(proposalId, approvedBy, approvalLevel);
    }
    
    /**
     * 정책 거부 감사 로그
     */
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
    
    /**
     * 정책 활성화 감사 로그
     */
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
        
        // 활성화 컴플라이언스 체크
        checkActivationCompliance(policyId, activatedBy);
    }
    
    /**
     * 정책 비활성화 감사 로그
     */
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
    
    /**
     * 정책 롤백 감사 로그
     */
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
    
    /**
     * 생성 컴플라이언스 체크
     */
    private void checkCreationCompliance(Long proposalId, String createdBy) {
        ComplianceCheckpoint checkpoint = new ComplianceCheckpoint("CREATION_COMPLIANCE");
        
        // 권한 체크
        if (!hasCreationPermission(createdBy)) {
            checkpoint.addViolation("User lacks policy creation permission");
        }
        
        // 정책 명명 규칙 체크
        if (!validatePolicyNamingConvention(proposalId)) {
            checkpoint.addViolation("Policy naming convention violated");
        }
        
        // 정책 내용 검증
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
    
    /**
     * 승인 컴플라이언스 체크
     */
    private void checkApprovalCompliance(Long proposalId, String approvedBy, String approvalLevel) {
        ComplianceCheckpoint checkpoint = new ComplianceCheckpoint("APPROVAL_COMPLIANCE");
        
        // 승인 권한 체크
        if (!hasApprovalPermission(approvedBy, approvalLevel)) {
            checkpoint.addViolation("User lacks appropriate approval permission for level: " + approvalLevel);
        }
        
        // 이해 상충 체크
        if (hasConflictOfInterest(proposalId, approvedBy)) {
            checkpoint.addViolation("Conflict of interest detected - approver created the proposal");
        }
        
        // 승인 타임라인 체크
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
    
    /**
     * 활성화 컴플라이언스 체크
     */
    private void checkActivationCompliance(Long policyId, String activatedBy) {
        ComplianceCheckpoint checkpoint = new ComplianceCheckpoint("ACTIVATION_COMPLIANCE");
        
        // 활성화 권한 체크
        if (!hasActivationPermission(activatedBy)) {
            checkpoint.addViolation("User lacks policy activation permission");
        }
        
        // 테스트 요구사항 체크
        if (!hasPassedRequiredTests(policyId)) {
            checkpoint.addViolation("Policy has not passed required tests");
        }
        
        // 문서화 요구사항 체크
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
    
    /**
     * 권한 검증 헬퍼 메서드들
     */
    private boolean hasCreationPermission(String user) {
        // 실제 구현: 사용자 권한 시스템과 연동
        return user != null && !user.isEmpty();
    }
    
    private boolean hasApprovalPermission(String user, String level) {
        // 실제 구현: 레벨별 승인 권한 체크
        return user != null && level != null;
    }
    
    private boolean hasActivationPermission(String user) {
        // 실제 구현: 활성화 권한 체크
        return user != null && !user.isEmpty();
    }
    
    private boolean hasConflictOfInterest(Long proposalId, String approver) {
        // 실제 구현: 제안자와 승인자가 동일한지 체크
        return false; // 간단한 구현
    }
    
    private boolean withinApprovalTimeline(Long proposalId) {
        // 실제 구현: 승인 타임라인 체크
        return true; // 간단한 구현
    }
    
    private boolean validatePolicyNamingConvention(Long proposalId) {
        // 실제 구현: 정책 명명 규칙 검증
        return true; // 간단한 구현
    }
    
    private boolean validatePolicyContent(Long proposalId) {
        // 실제 구현: 정책 내용 검증
        return true; // 간단한 구현
    }
    
    private boolean hasPassedRequiredTests(Long policyId) {
        // 실제 구현: 테스트 통과 여부 체크
        return true; // 간단한 구현
    }
    
    private boolean hasRequiredDocumentation(Long policyId) {
        // 실제 구현: 문서화 요구사항 체크
        return true; // 간단한 구현
    }
    
    /**
     * 컴플라이언스 보고서 생성
     */
    public ComplianceReport generateComplianceReport(LocalDateTime startDate, LocalDateTime endDate) {
        ComplianceReport report = new ComplianceReport();
        report.setReportId(UUID.randomUUID().toString());
        report.setGeneratedAt(LocalDateTime.now());
        report.setStartDate(startDate);
        report.setEndDate(endDate);
        
        // 기간 내 감사 로그 필터링
        List<AuditLogEntry> periodLogs = auditLogs.values().stream()
            .filter(log -> log.timestamp.isAfter(startDate) && log.timestamp.isBefore(endDate))
            .collect(Collectors.toList());
        
        report.setTotalEvents(periodLogs.size());
        
        // 이벤트 타입별 집계
        Map<String, Long> eventTypeCounts = periodLogs.stream()
            .collect(Collectors.groupingBy(
                log -> log.eventType,
                Collectors.counting()
            ));
        report.setEventTypeCounts(eventTypeCounts);
        
        // 컴플라이언스 위반 집계
        List<ComplianceCheckpoint> periodCheckpoints = complianceCheckpoints.values().stream()
            .filter(cp -> cp.timestamp.isAfter(startDate) && cp.timestamp.isBefore(endDate))
            .collect(Collectors.toList());
        
        long totalViolations = periodCheckpoints.stream()
            .filter(cp -> !cp.isCompliant())
            .count();
        report.setTotalViolations(totalViolations);
        
        // 위반 유형별 집계
        Map<String, List<String>> violationsByType = periodCheckpoints.stream()
            .filter(cp -> !cp.isCompliant())
            .collect(Collectors.groupingBy(
                cp -> cp.complianceType,
                Collectors.flatMapping(cp -> cp.violations.stream(), Collectors.toList())
            ));
        report.setViolationsByType(violationsByType);
        
        // 컴플라이언스 점수 계산 (0-100)
        double complianceScore = periodCheckpoints.isEmpty() ? 100.0 :
            (double)(periodCheckpoints.size() - totalViolations) / periodCheckpoints.size() * 100;
        report.setComplianceScore(complianceScore);
        
        // 권장사항 생성
        List<String> recommendations = generateRecommendations(violationsByType);
        report.setRecommendations(recommendations);
        
        log.info("Compliance Report Generated: {} events, {} violations, {:.2f}% compliance score",
            report.getTotalEvents(), report.getTotalViolations(), report.getComplianceScore());
        
        return report;
    }
    
    /**
     * 권장사항 생성
     */
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
    
    /**
     * 컴플라이언스 보고서 클래스
     */
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
        
        // Getters and Setters
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
    
    /**
     * 주기적 컴플라이언스 체크 (매일 자정)
     */
//    @Scheduled(cron = "0 0 0 * * *")
    public void performDailyComplianceCheck() {
        log.info("Starting daily compliance check...");
        
        LocalDateTime yesterday = LocalDateTime.now().minusDays(1);
        LocalDateTime today = LocalDateTime.now();
        
        ComplianceReport dailyReport = generateComplianceReport(yesterday, today);
        
        if (dailyReport.getComplianceScore() < 80.0) {
            log.warn("Daily compliance score below threshold: {:.2f}%", dailyReport.getComplianceScore());
            // 알림 발송 로직
        }
        
        // 오래된 로그 정리 (30일 이상)
        cleanupOldLogs();
    }
    
    /**
     * 오래된 로그 정리
     */
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
    
    /**
     * 감사 로그 검색
     */
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
    
    /**
     * 컴플라이언스 체크포인트 검색
     */
    public List<ComplianceCheckpoint> searchComplianceCheckpoints(String complianceType, 
                                                                  boolean violationsOnly) {
        return complianceCheckpoints.values().stream()
            .filter(cp -> complianceType == null || cp.complianceType.equals(complianceType))
            .filter(cp -> !violationsOnly || !cp.isCompliant())
            .sorted(Comparator.comparing(cp -> cp.timestamp))
            .collect(Collectors.toList());
    }
}