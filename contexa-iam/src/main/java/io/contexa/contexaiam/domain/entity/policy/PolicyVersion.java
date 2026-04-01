package io.contexa.contexaiam.domain.entity.policy;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Stores policy snapshots for version history, rollback, and diff comparison.
 * Each create/update/delete operation creates a new version record.
 */
@Entity
@Table(name = "POLICY_VERSION", indexes = {
        @Index(name = "idx_policy_version_policy_id", columnList = "policy_id"),
        @Index(name = "idx_policy_version_changed_at", columnList = "changed_at")
})
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class PolicyVersion implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "policy_id", nullable = false)
    private Long policyId;

    @Column(name = "version_number", nullable = false)
    private int versionNumber;

    @Column(name = "snapshot_json", nullable = false, columnDefinition = "TEXT")
    private String snapshotJson;

    @Enumerated(EnumType.STRING)
    @Column(name = "change_type", nullable = false, length = 20)
    private ChangeType changeType;

    @Column(name = "changed_by", nullable = false)
    private String changedBy;

    @Column(name = "change_reason", length = 1024)
    private String changeReason;

    @Column(name = "changed_at", nullable = false, updatable = false)
    @Builder.Default
    private LocalDateTime changedAt = LocalDateTime.now();

    public enum ChangeType {
        CREATED,
        UPDATED,
        DELETED,
        ROLLBACK
    }

    @PrePersist
    protected void onCreate() {
        if (this.changedAt == null) {
            this.changedAt = LocalDateTime.now();
        }
    }
}
