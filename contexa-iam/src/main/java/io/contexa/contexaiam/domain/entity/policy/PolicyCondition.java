/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.domain.entity.policy;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;

@Entity
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class PolicyCondition implements Serializable {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
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
