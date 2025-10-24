package io.contexa.contexaiam.domain.entity.policy;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;

/**
 * 규칙을 구성하는 개별 조건을 정의하는 엔티티.
 * SpEL 표현식을 사용하여 동적인 조건을 명시합니다.
 */
@Entity
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class PolicyCondition implements Serializable {
    @Id @GeneratedValue
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "rule_id", nullable = false)
    private PolicyRule rule;

    @Column(name = "condition_expression", length = 2048, nullable = false)
    private String expression; // 예: "hasRole('ADMIN')", "#risk.score < 70"

    @Enumerated(EnumType.STRING)
    @Column(name = "authorization_phase", nullable = false)
    @Builder.Default
    private AuthorizationPhase authorizationPhase = AuthorizationPhase.PRE_AUTHORIZE;

    private String description;

    public enum AuthorizationPhase {
        PRE_AUTHORIZE,
        POST_AUTHORIZE
    }
}
