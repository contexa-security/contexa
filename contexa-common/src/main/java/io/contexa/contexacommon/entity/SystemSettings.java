package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "system_settings")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SystemSettings {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    @Builder.Default
    private int auditLogRetentionDays = 90;

    @Column(nullable = false, length = 100)
    @Builder.Default
    private String defaultRole = "ROLE_USER";

    @Column(nullable = false, length = 50)
    @Builder.Default
    private String policyCombiningAlgorithm = "FIRST_APPLICABLE";

    @Column(nullable = false)
    @Builder.Default
    private boolean registrationEnabled = false;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) this.createdAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}
