package io.contexa.contexacore.domain.entity;

import io.contexa.contexacore.utils.JpaListConverter;
import io.contexa.contexacore.utils.JpaMapConverter;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "soar_approval_requests")
@Getter
@Setter
@EntityListeners(AuditingEntityListener.class)
public class SoarApprovalRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, updatable = false, length = 100)
    private String requestId;

    @Column(nullable = false, updatable = false, length = 100)
    private String playbookInstanceId;

    @Column(name = "incident_id", length = 100)
    private String incidentId;

    @Column(name = "session_id", length = 128)
    private String sessionId;

    @Column(name = "risk_level", length = 20)
    private String riskLevel;

    @Column(name = "approval_type", length = 50)
    private String approvalType;

    @Column(name = "requested_by", length = 255)
    private String requestedBy;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @Column(name = "action_type", length = 50)
    private String actionType;

    @Column(name = "approval_timeout")
    private Integer approvalTimeout;

    @Column(nullable = false, updatable = false, length = 255)
    private String actionName;

    @Column(name = "tool_name", length = 255)
    private String toolName;

    @Column(columnDefinition = "TEXT", updatable = false)
    private String description;

    @Convert(converter = JpaMapConverter.class)
    @Column(columnDefinition = "TEXT", updatable = false)
    private Map<String, Object> parameters;

    @Column(nullable = false, length = 30)
    private String status;

    @Column(length = 255)
    private String reviewerId;

    @Column(name = "approved_by", length = 255)
    private String approvedBy;

    @Column(name = "organization_id", length = 100)
    private String organizationId;

    @Column(name = "reviewer_comment", columnDefinition = "TEXT")
    private String reviewerComment;

    @Column(name = "approval_comment", columnDefinition = "TEXT")
    private String approvalComment;

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @Column
    private Integer requiredApprovers;

    @Convert(converter = JpaListConverter.class)
    @Column(columnDefinition = "TEXT")
    private List<String> requiredRoles;

    @Column(name = "approved_count")
    private Integer approvedCount;

    @Column(name = "rejected_count")
    private Integer rejectedCount;

    @Column(name = "remaining_approvals")
    private Integer remainingApprovals;

    @Column(name = "quorum_satisfied", nullable = false, columnDefinition = "boolean default false")
    private boolean quorumSatisfied;

    @Column(name = "current_step_number")
    private Integer currentStepNumber;

    @Column(name = "total_steps")
    private Integer totalSteps;

    @Column(name = "reopened_from_request_id", length = 100)
    private String reopenedFromRequestId;

    @Column(name = "break_glass_requested", nullable = false, columnDefinition = "boolean default false")
    private boolean breakGlassRequested;

    @Column(name = "break_glass_reason", columnDefinition = "TEXT")
    private String breakGlassReason;
}
