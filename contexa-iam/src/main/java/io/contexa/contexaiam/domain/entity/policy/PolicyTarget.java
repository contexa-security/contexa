package io.contexa.contexaiam.domain.entity.policy;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;

/**
 * 정책이 적용될 대상을 정의하는 엔티티.
 */
@Entity
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class PolicyTarget implements Serializable {
    @Id @GeneratedValue
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", nullable = false)
    @JsonBackReference("policy-targets")
    private Policy policy;

    @Column(nullable = false)
    private String targetType; // 예: "URL", "METHOD"

    @Column(nullable = false)
    private String targetIdentifier; // 예: "/admin/**", "com.example.service.AdminService.deleteUser"

    @Column
    private String httpMethod; // 예: "GET", "POST", "ALL"
}