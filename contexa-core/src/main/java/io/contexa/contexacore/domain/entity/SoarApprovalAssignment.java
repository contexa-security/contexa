package io.contexa.contexacore.domain.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "soar_approval_assignments",
        indexes = {
                @Index(name = "idx_soar_approval_assignment_request_id", columnList = "request_id"),
                @Index(name = "idx_soar_approval_assignment_status", columnList = "status"),
                @Index(name = "idx_soar_approval_assignment_step", columnList = "request_id,step_number")
        }
)
@Getter
@Setter
@EntityListeners(AuditingEntityListener.class)
public class SoarApprovalAssignment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_id", nullable = false, length = 100)
    private String requestId;

    @Column(name = "step_number", nullable = false)
    private Integer stepNumber;

    @Column(name = "assignee_id", length = 100)
    private String assigneeId;

    @Column(name = "assignee_role", length = 100)
    private String assigneeRole;

    @Column(name = "status", nullable = false, length = 30)
    private String status;

    @Column(name = "assigned_by", length = 100)
    private String assignedBy;

    @Column(name = "assigned_at")
    private LocalDateTime assignedAt;

    @Column(name = "responded_at")
    private LocalDateTime respondedAt;

    @Column(name = "response_decision", length = 30)
    private String responseDecision;

    @Column(name = "response_comment", columnDefinition = "TEXT")
    private String responseComment;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}
