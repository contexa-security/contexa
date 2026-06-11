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
package io.contexa.contexaiam.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "BLOCKED_USER")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BlockedUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "username")
    private String username;

    @Column(name = "request_id", nullable = false, unique = true)
    private String requestId;

    @Column(name = "risk_score")
    private Double riskScore;

    @Column(name = "confidence")
    private Double confidence;

    @Column(name = "reasoning", columnDefinition = "TEXT")
    private String reasoning;

    @Column(name = "blocked_at", nullable = false)
    private LocalDateTime blockedAt;

    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;

    @Column(name = "resolved_by")
    private String resolvedBy;

    @Column(name = "resolved_action")
    private String resolvedAction;

    @Column(name = "resolve_reason", columnDefinition = "TEXT")
    private String resolveReason;

    @Column(name = "block_count", nullable = false)
    @Builder.Default
    private Integer blockCount = 1;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    @Builder.Default
    private BlockedUserStatus status = BlockedUserStatus.BLOCKED;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "unblock_requested_at")
    private LocalDateTime unblockRequestedAt;

    @Column(name = "unblock_reason", columnDefinition = "TEXT")
    private String unblockReason;

    @Column(name = "mfa_verified")
    @Builder.Default
    private Boolean mfaVerified = false;

    @Column(name = "mfa_verified_at")
    private LocalDateTime mfaVerifiedAt;
}
