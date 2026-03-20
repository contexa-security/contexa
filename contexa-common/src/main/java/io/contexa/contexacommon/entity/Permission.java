package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.time.LocalDateTime;

@Entity
@Table(name = "permission")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Permission implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "permission_id")
    private Long id;

    @Column(name = "permission_name", unique = true, nullable = false)
    private String name;

    @Column(name = "friendly_name")
    private String friendlyName;

    @Column(name = "description", length = 1024)
    private String description;

    @Column(name = "target_type", length = 100)
    private String targetType;

    @Column(name = "action_type", length = 100)
    private String actionType;

    @Column(name = "condition_expression", length = 2048)
    private String conditionExpression;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "managed_resource_id", unique = true)
    private ManagedResource managedResource;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
