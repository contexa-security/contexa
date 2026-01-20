package io.contexa.contexaiam.domain.entity.policy;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;


@Entity
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class PolicyCondition implements Serializable {
    @Id @GeneratedValue
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "rule_id", nullable = false)
    @JsonBackReference("rule-conditions")
    private PolicyRule rule;

    @Column(name = "condition_expression", length = 2048, nullable = false)
    private String expression; 

    @Enumerated(EnumType.STRING)
    @Column(name = "authorization_phase", nullable = false)
    @Builder.Default
    private AuthorizationPhase authorizationPhase = AuthorizationPhase.PRE_AUTHORIZE;

    private String description;

    public enum AuthorizationPhase {
        PRE_AUTHORIZE,
        POST_AUTHORIZE,
        PROTECTABLE
    }
}
