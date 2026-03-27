package io.contexa.contexaiam.domain.entity.policy;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;

@Entity
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class PolicyTarget implements Serializable {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", nullable = false)
    @JsonBackReference("policy-targets")
    private Policy policy;

    @Column(nullable = false)
    private String targetType; 

    @Column(nullable = false)
    private String targetIdentifier; 

    @Column
    private String httpMethod;

    @Column(name = "target_order", nullable = false)
    @Builder.Default
    private int targetOrder = 0;

    @Column(name = "source_type", length = 20)
    @Builder.Default
    private String sourceType = "RESOURCE";
}