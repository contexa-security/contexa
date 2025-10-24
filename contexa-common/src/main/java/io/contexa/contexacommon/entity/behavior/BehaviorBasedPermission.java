package io.contexa.contexacommon.entity.behavior;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "behavior_based_permissions")
@Getter
@Setter
public class BehaviorBasedPermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "condition_expression", columnDefinition = "TEXT")
    private String conditionExpression;

    @Column(name = "applicable_to", length = 50)
    private String applicableTo;

    @Column(name = "permission_adjustment", length = 50)
    private String permissionAdjustment;

    @Column(name = "is_active")
    private boolean active = true;

    @Column(name = "priority")
    private Integer priority = 100;

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;
}