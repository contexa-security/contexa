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

    @Column(unique = true, nullable = false, updatable = false)
    private String requestId;

    @Column(nullable = false, updatable = false)
    private String playbookInstanceId;

    @Column(name = "incident_id")
    private String incidentId;

    @Column(name = "session_id")
    private String sessionId;

    @Column(name = "risk_level")
    private String riskLevel;

    @Column(name = "approval_type")
    private String approvalType;

    @Column(name = "requested_by")
    private String requestedBy;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @Column(name = "action_type")
    private String actionType;

    @Column(name = "approval_timeout")
    private Integer approvalTimeout;

    @Column(nullable = false, updatable = false)
    private String actionName;

    @Column(name = "tool_name")
    private String toolName;

    @Column(columnDefinition = "TEXT", updatable = false)
    private String description;

    @Convert(converter = JpaMapConverter.class)
    @Column(columnDefinition = "TEXT", updatable = false)
    private Map<String, Object> parameters;

    @Column(nullable = false)
    private String status;

    @Column
    private String reviewerId;

    @Column(name = "approved_by")
    private String approvedBy;

    private String organizationId;

    @Column(columnDefinition = "TEXT")
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

    @Column(name = "reopened_from_request_id")
    private String reopenedFromRequestId;

    @Column(name = "break_glass_requested", nullable = false, columnDefinition = "boolean default false")
    private boolean breakGlassRequested;

    @Column(name = "break_glass_reason", columnDefinition = "TEXT")
    private String breakGlassReason;
}
