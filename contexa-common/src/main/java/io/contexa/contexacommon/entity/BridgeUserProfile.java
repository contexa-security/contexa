package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "bridge_user_profile")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BridgeUserProfile {

    @Id
    private Long userId;

    @MapsId
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private Users user;

    @Column(length = 100)
    private String sourceSystem;

    @Column(length = 100)
    private String authenticationType;

    @Column(length = 100)
    private String authenticationAssurance;

    @Column
    private Boolean mfaCompletedFromCustomer;

    @Column(length = 255)
    private String sessionId;

    @Column(columnDefinition = "TEXT")
    private String lastAuthoritiesJson;

    @Column(columnDefinition = "TEXT")
    private String lastAttributesJson;

    @Column(length = 128)
    private String lastSyncHash;

    @Column
    private LocalDateTime lastSyncedAt;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
