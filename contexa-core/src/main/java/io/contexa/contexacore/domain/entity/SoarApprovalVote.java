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
        name = "soar_approval_votes",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_soar_approval_vote_request_approver_step",
                        columnNames = {"request_id", "approver_id", "step_number"}
                )
        },
        indexes = {
                @Index(name = "idx_soar_approval_vote_request_id", columnList = "request_id"),
                @Index(name = "idx_soar_approval_vote_decision", columnList = "decision"),
                @Index(name = "idx_soar_approval_vote_created_at", columnList = "created_at"),
                @Index(name = "idx_soar_approval_vote_request_step", columnList = "request_id,step_number")
        }
)
@Getter
@Setter
@EntityListeners(AuditingEntityListener.class)
public class SoarApprovalVote {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_id", nullable = false, length = 100)
    private String requestId;

    @Column(name = "approver_id", nullable = false, length = 100)
    private String approverId;

    @Column(name = "approver_name", length = 150)
    private String approverName;

    @Column(name = "approver_role", nullable = false, length = 100)
    private String approverRole;

    @Column(name = "decision", nullable = false, length = 20)
    private String decision;

    @Column(name = "comment", columnDefinition = "TEXT")
    private String comment;

    @Column(name = "step_number", nullable = false)
    private Integer stepNumber;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public boolean isApproved() {
        return "APPROVED".equalsIgnoreCase(decision);
    }

    public boolean isRejected() {
        return "REJECTED".equalsIgnoreCase(decision);
    }
}
