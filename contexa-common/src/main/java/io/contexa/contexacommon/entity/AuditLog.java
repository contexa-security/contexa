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
package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "ctxa_audit_log")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class) 
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, updatable = false)
    @CreatedDate 
    private LocalDateTime timestamp;

    @Column(nullable = false, length = 255)
    private String principalName;

    @Column(nullable = false, length = 512)
    private String resourceIdentifier; 

    @Column(length = 100)
    private String action;

    @Column(nullable = false, length = 50)
    private String decision;

    @Column(length = 1024)
    private String reason; 

    @Column(length = 50)
    private String outcome;

    @Column(length = 1024)
    private String resourceUri;

    @Column(length = 45)
    private String clientIp;
    @Column(length = 128)
    private String sessionId;

    @Column(columnDefinition = "TEXT")
    private String details;

    @Column(length = 50)
    private String eventCategory;

    @Column(length = 512)
    private String userAgent;

    @Column(length = 10)
    private String httpMethod;

    @Column(length = 2048)
    private String requestUri;

    private Double riskScore;

    @Column(length = 50)
    private String eventSource;

    @Column(length = 64)
    private String correlationId;

    /** docs/agent A5-5: who the decided request acted as (HUMAN_USER, DELEGATED_AGENT, AUTONOMOUS_AGENT, ...). */
    @Column(length = 32)
    private String subjectKind;

    /** docs/agent A5-5: the agent of an agent's request. */
    @Column(length = 255)
    private String agentId;

    /** docs/agent A5-5: the person a delegated agent acted for. */
    @Column(length = 255)
    private String delegatorId;

    /** docs/agent A5-5: the delegation the agent's request ran under, when known. */
    @Column(length = 255)
    private String delegationId;

    /** docs/agent A5-5: the operation the request asked for (its action family). */
    @Column(length = 100)
    private String targetAction;

    /** docs/agent A5-5: the risk facts the decision cited (its reason codes with their fact IDs). */
    @Column(length = 1024)
    private String riskState;

    /** docs/agent A5-5: what was enforced (the decision applied, kept stricter or only observed, and later steps). */
    @Column(length = 255)
    private String enforcementAction;

    /** docs/agent A5-5: why it was enforced so (the model's decision, a technical fallback, a constraint). */
    @Column(length = 1024)
    private String enforcementCause;

    /** docs/agent A5-5: the SHA-256 of the request's context (time, agent, target, action, normalised input). */
    @Column(length = 64)
    private String requestContextHash;

    /** docs/agent A5-6: the tenant of the decided request. */
    @Column(length = 255)
    private String tenantId;

    /** docs/agent A5-6: the SHA-256 of the decision record, its tenant, user and time included. */
    @Column(length = 64)
    private String recordHash;

    /** docs/agent A5-6: the hash of the decision record written before this one. */
    @Column(length = 64)
    private String previousRecordHash;

    /** docs/agent A5-6: the keyed signature of the record hash. */
    @Column(length = 128)
    private String recordSignature;

    /** docs/agent A5-6: the key the signature was made with. */
    @Column(length = 64)
    private String signatureKeyId;

    @PrePersist
    protected void onCreate() {
        if (this.timestamp == null) {
            this.timestamp = LocalDateTime.now();
        }
    }
}
