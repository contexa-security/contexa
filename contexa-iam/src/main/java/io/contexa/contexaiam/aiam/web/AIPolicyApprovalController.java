package io.contexa.contexaiam.aiam.web;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.service.PolicyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * AI Policy Approval Controller
 *
 * AI가 생성하거나 진화시킨 정책의 승인/거부를 처리하는 REST API 컨트롤러입니다.
 *
 * @author contexa
 * @since 3.1.0
 */
@Slf4j
@RestController
@RequestMapping("/api/ai/policies")
@RequiredArgsConstructor
public class AIPolicyApprovalController {

    private final PolicyService policyService;

    /**
     * AI 생성 정책 목록 조회 (승인 대기 중)
     */
    @GetMapping("/pending")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('POLICY_APPROVE')")
    public ResponseEntity<Page<PolicyDTO>> getPendingAIPolicies(Pageable pageable) {
        log.info("AI 생성 정책 목록 조회 (승인 대기)");

        Page<Policy> pendingPolicies = policyService.findPendingAIPolicies(pageable);
        Page<PolicyDTO> policyDTOs = pendingPolicies.map(this::convertToDTO);

        return ResponseEntity.ok(policyDTOs);
    }

    /**
     * 모든 AI 생성 정책 목록 조회
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('POLICY_VIEW')")
    public ResponseEntity<Page<PolicyDTO>> getAllAIPolicies(
            @RequestParam(required = false) Policy.PolicySource source,
            @RequestParam(required = false) Policy.ApprovalStatus status,
            Pageable pageable) {

        log.info("AI 생성 정책 목록 조회 - source: {}, status: {}", source, status);

        Page<Policy> policies = policyService.findAIPolicies(source, status, pageable);
        Page<PolicyDTO> policyDTOs = policies.map(this::convertToDTO);

        return ResponseEntity.ok(policyDTOs);
    }

    /**
     * 특정 AI 정책 상세 조회
     */
    @GetMapping("/{policyId}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('POLICY_VIEW')")
    public ResponseEntity<PolicyDetailDTO> getAIPolicy(@PathVariable Long policyId) {
        log.info("AI 정책 상세 조회: {}", policyId);

        Policy policy = policyService.findById(policyId);
        if (policy == null || !policy.isAIGenerated()) {
            return ResponseEntity.notFound().build();
        }

        PolicyDetailDTO detailDTO = convertToDetailDTO(policy);
        return ResponseEntity.ok(detailDTO);
    }

    /**
     * AI 정책 승인
     */
    @PostMapping("/{policyId}/approve")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('POLICY_APPROVE')")
    public ResponseEntity<ApprovalResponseDTO> approvePolicy(
            @PathVariable Long policyId,
            @RequestBody(required = false) ApprovalRequestDTO request,
            Principal principal) {

        log.info("AI 정책 승인 요청 - policyId: {}, approver: {}", policyId, principal.getName());

        try {
            Policy policy = policyService.findById(policyId);
            if (policy == null || !policy.isAIGenerated()) {
                return ResponseEntity.notFound().build();
            }

            if (!policy.requiresApproval()) {
                return ResponseEntity.badRequest()
                    .body(new ApprovalResponseDTO(false, "정책이 이미 처리되었습니다."));
            }

            // 정책 승인 처리
            policy.approve(principal.getName());
            if (request != null && request.isActivateImmediately()) {
                policy.activate();
            }

            policyService.save(policy);

            // 응답 생성
            ApprovalResponseDTO response = new ApprovalResponseDTO(
                true,
                "정책이 성공적으로 승인되었습니다.",
                policy.getId(),
                policy.getName(),
                policy.getApprovalStatus(),
                principal.getName(),
                LocalDateTime.now()
            );

            log.info("AI 정책 승인 완료 - policyId: {}", policyId);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("AI 정책 승인 실패 - policyId: {}", policyId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApprovalResponseDTO(false, "승인 처리 중 오류가 발생했습니다: " + e.getMessage()));
        }
    }

    /**
     * AI 정책 거부
     */
    @PostMapping("/{policyId}/reject")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('POLICY_APPROVE')")
    public ResponseEntity<ApprovalResponseDTO> rejectPolicy(
            @PathVariable Long policyId,
            @RequestBody RejectRequestDTO request,
            Principal principal) {

        log.info("AI 정책 거부 요청 - policyId: {}, rejector: {}", policyId, principal.getName());

        try {
            Policy policy = policyService.findById(policyId);
            if (policy == null || !policy.isAIGenerated()) {
                return ResponseEntity.notFound().build();
            }

            if (!policy.requiresApproval()) {
                return ResponseEntity.badRequest()
                    .body(new ApprovalResponseDTO(false, "정책이 이미 처리되었습니다."));
            }

            // 정책 거부 처리
            policy.reject(principal.getName());
            policyService.save(policy);

            // 거부 사유 기록 (학습용)
            if (request != null && request.getReason() != null) {
                policyService.recordRejectionReason(policy.getId(), request.getReason());
            }

            // 응답 생성
            ApprovalResponseDTO response = new ApprovalResponseDTO(
                true,
                "정책이 거부되었습니다.",
                policy.getId(),
                policy.getName(),
                policy.getApprovalStatus(),
                principal.getName(),
                LocalDateTime.now()
            );

            log.info("AI 정책 거부 완료 - policyId: {}, reason: {}", policyId, request.getReason());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("AI 정책 거부 실패 - policyId: {}", policyId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApprovalResponseDTO(false, "거부 처리 중 오류가 발생했습니다: " + e.getMessage()));
        }
    }

    /**
     * AI 정책 통계 조회
     */
    @GetMapping("/statistics")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('POLICY_VIEW')")
    public ResponseEntity<Map<String, Object>> getAIPolicyStatistics() {
        log.info("AI 정책 통계 조회");

        Map<String, Object> statistics = new HashMap<>();

        // 전체 AI 정책 수
        long totalAIPolicies = policyService.countAIPolicies();
        statistics.put("total", totalAIPolicies);

        // 상태별 정책 수
        Map<String, Long> statusCounts = policyService.countAIPoliciesByStatus();
        statistics.put("byStatus", statusCounts);

        // 출처별 정책 수
        Map<String, Long> sourceCounts = policyService.countAIPoliciesBySource();
        statistics.put("bySource", sourceCounts);

        // 최근 30일 승인율
        double approvalRate = policyService.calculateApprovalRate(30);
        statistics.put("approvalRate", approvalRate);

        // 평균 신뢰도 점수
        double avgConfidenceScore = policyService.calculateAverageConfidenceScore();
        statistics.put("avgConfidenceScore", avgConfidenceScore);

        return ResponseEntity.ok(statistics);
    }

    /**
     * AI 정책 일괄 승인
     */
    @PostMapping("/batch/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<BatchApprovalResponseDTO> batchApprove(
            @RequestBody BatchApprovalRequestDTO request,
            Principal principal) {

        log.info("AI 정책 일괄 승인 요청 - count: {}, approver: {}",
                request.getPolicyIds().size(), principal.getName());

        BatchApprovalResponseDTO response = new BatchApprovalResponseDTO();

        for (Long policyId : request.getPolicyIds()) {
            try {
                Policy policy = policyService.findById(policyId);
                if (policy != null && policy.isAIGenerated() && policy.requiresApproval()) {
                    policy.approve(principal.getName());
                    if (request.isActivateImmediately()) {
                        policy.activate();
                    }
                    policyService.save(policy);
                    response.addSuccess(policyId);
                } else {
                    response.addSkipped(policyId, "조건 불충족");
                }
            } catch (Exception e) {
                response.addFailed(policyId, e.getMessage());
            }
        }

        log.info("AI 정책 일괄 승인 완료 - 성공: {}, 실패: {}, 건너뜀: {}",
                response.getSuccessCount(), response.getFailedCount(), response.getSkippedCount());

        return ResponseEntity.ok(response);
    }

    // ==================== DTO Classes ====================

    /**
     * 정책 DTO
     */
    public static class PolicyDTO {
        public Long id;
        public String name;
        public String description;
        public Policy.PolicySource source;
        public Policy.ApprovalStatus approvalStatus;
        public Double confidenceScore;
        public String aiModel;
        public LocalDateTime createdAt;
        public boolean isActive;
    }

    /**
     * 정책 상세 DTO
     */
    public static class PolicyDetailDTO extends PolicyDTO {
        public Policy.Effect effect;
        public int priority;
        public String approvedBy;
        public LocalDateTime approvedAt;
        public String friendlyDescription;
        public List<String> targets;
        public List<String> rules;
    }

    /**
     * 승인 요청 DTO
     */
    public static class ApprovalRequestDTO {
        private boolean activateImmediately = true;
        private String comment;

        public boolean isActivateImmediately() { return activateImmediately; }
        public void setActivateImmediately(boolean activateImmediately) {
            this.activateImmediately = activateImmediately;
        }
        public String getComment() { return comment; }
        public void setComment(String comment) { this.comment = comment; }
    }

    /**
     * 거부 요청 DTO
     */
    public static class RejectRequestDTO {
        private String reason;
        private String comment;

        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        public String getComment() { return comment; }
        public void setComment(String comment) { this.comment = comment; }
    }

    /**
     * 승인/거부 응답 DTO
     */
    public static class ApprovalResponseDTO {
        private boolean success;
        private String message;
        private Long policyId;
        private String policyName;
        private Policy.ApprovalStatus status;
        private String processedBy;
        private LocalDateTime processedAt;

        public ApprovalResponseDTO(boolean success, String message) {
            this.success = success;
            this.message = message;
        }

        public ApprovalResponseDTO(boolean success, String message, Long policyId,
                                  String policyName, Policy.ApprovalStatus status,
                                  String processedBy, LocalDateTime processedAt) {
            this.success = success;
            this.message = message;
            this.policyId = policyId;
            this.policyName = policyName;
            this.status = status;
            this.processedBy = processedBy;
            this.processedAt = processedAt;
        }

        // Getters
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public Long getPolicyId() { return policyId; }
        public String getPolicyName() { return policyName; }
        public Policy.ApprovalStatus getStatus() { return status; }
        public String getProcessedBy() { return processedBy; }
        public LocalDateTime getProcessedAt() { return processedAt; }
    }

    /**
     * 일괄 승인 요청 DTO
     */
    public static class BatchApprovalRequestDTO {
        private List<Long> policyIds;
        private boolean activateImmediately = true;

        public List<Long> getPolicyIds() { return policyIds; }
        public void setPolicyIds(List<Long> policyIds) { this.policyIds = policyIds; }
        public boolean isActivateImmediately() { return activateImmediately; }
        public void setActivateImmediately(boolean activateImmediately) {
            this.activateImmediately = activateImmediately;
        }
    }

    /**
     * 일괄 승인 응답 DTO
     */
    public static class BatchApprovalResponseDTO {
        private List<Long> successIds = new java.util.ArrayList<>();
        private Map<Long, String> failedIds = new HashMap<>();
        private Map<Long, String> skippedIds = new HashMap<>();

        public void addSuccess(Long id) { successIds.add(id); }
        public void addFailed(Long id, String reason) { failedIds.put(id, reason); }
        public void addSkipped(Long id, String reason) { skippedIds.put(id, reason); }

        public int getSuccessCount() { return successIds.size(); }
        public int getFailedCount() { return failedIds.size(); }
        public int getSkippedCount() { return skippedIds.size(); }

        public List<Long> getSuccessIds() { return successIds; }
        public Map<Long, String> getFailedIds() { return failedIds; }
        public Map<Long, String> getSkippedIds() { return skippedIds; }
    }

    // ==================== Helper Methods ====================

    private PolicyDTO convertToDTO(Policy policy) {
        PolicyDTO dto = new PolicyDTO();
        dto.id = policy.getId();
        dto.name = policy.getName();
        dto.description = policy.getDescription();
        dto.source = policy.getSource();
        dto.approvalStatus = policy.getApprovalStatus();
        dto.confidenceScore = policy.getConfidenceScore();
        dto.aiModel = policy.getAiModel();
        dto.createdAt = policy.getCreatedAt();
        dto.isActive = policy.getIsActive();
        return dto;
    }

    private PolicyDetailDTO convertToDetailDTO(Policy policy) {
        PolicyDetailDTO dto = new PolicyDetailDTO();
        dto.id = policy.getId();
        dto.name = policy.getName();
        dto.description = policy.getDescription();
        dto.source = policy.getSource();
        dto.approvalStatus = policy.getApprovalStatus();
        dto.confidenceScore = policy.getConfidenceScore();
        dto.aiModel = policy.getAiModel();
        dto.createdAt = policy.getCreatedAt();
        dto.isActive = policy.getIsActive();
        dto.effect = policy.getEffect();
        dto.priority = policy.getPriority();
        dto.approvedBy = policy.getApprovedBy();
        dto.approvedAt = policy.getApprovedAt();
        dto.friendlyDescription = policy.getFriendlyDescription();

        // targets와 rules 변환
        dto.targets = policy.getTargets().stream()
            .map(target -> target.toString())
            .collect(java.util.stream.Collectors.toList());
        dto.rules = policy.getRules().stream()
            .map(rule -> rule.toString())
            .collect(java.util.stream.Collectors.toList());

        return dto;
    }
}