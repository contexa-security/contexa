package io.contexa.contexacore.domain.entity;

import io.contexa.contexacore.utils.JpaListConverter;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(
        name = "soar_approval_steps",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_soar_approval_step_request_number",
                        columnNames = {"request_id", "step_number"}
                )
        },
        indexes = {
                @Index(name = "idx_soar_approval_step_request_id", columnList = "request_id"),
                @Index(name = "idx_soar_approval_step_status", columnList = "status")
        }
)
@Getter
@Setter
@EntityListeners(AuditingEntityListener.class)
public class SoarApprovalStep {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_id", nullable = false, length = 100)
    private String requestId;

    @Column(name = "step_number", nullable = false)
    private Integer stepNumber;

    @Column(name = "step_name", nullable = false, length = 150)
    private String stepName;

    @Column(name = "status", nullable = false, length = 30)
    private String status;

    @Column(name = "required_approvers", nullable = false)
    private Integer requiredApprovers;

    @Column(name = "approved_count", nullable = false)
    private Integer approvedCount;

    @Column(name = "rejected_count", nullable = false)
    private Integer rejectedCount;

    @Column(name = "remaining_approvals", nullable = false)
    private Integer remainingApprovals;

    @Convert(converter = JpaListConverter.class)
    @Column(name = "required_roles", columnDefinition = "TEXT")
    private List<String> requiredRoles;

    @Column(name = "opened_at")
    private LocalDateTime openedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}
