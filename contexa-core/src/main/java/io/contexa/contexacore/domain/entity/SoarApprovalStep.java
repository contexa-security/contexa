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
package io.contexa.contexacore.domain.entity;

import io.contexa.contexacore.utils.JpaListConverter;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(
        name = "soar_approval_steps",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_soar_approval_step_request_number",
                        columnNames = {"request_id", "step_number"}
                )
        },
        indexes = {
                @Index(name = "idx_soar_approval_step_request_id", columnList = "request_id"),
                @Index(name = "idx_soar_approval_step_status", columnList = "status")
        }
)
@Getter
@Setter
@EntityListeners(AuditingEntityListener.class)
public class SoarApprovalStep {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_id", nullable = false, length = 100)
    private String requestId;

    @Column(name = "step_number", nullable = false)
    private Integer stepNumber;

    @Column(name = "step_name", nullable = false, length = 150)
    private String stepName;

    @Column(name = "status", nullable = false, length = 30)
    private String status;

    @Column(name = "required_approvers", nullable = false)
    private Integer requiredApprovers;

    @Column(name = "approved_count", nullable = false)
    private Integer approvedCount;

    @Column(name = "rejected_count", nullable = false)
    private Integer rejectedCount;

    @Column(name = "remaining_approvals", nullable = false)
    private Integer remainingApprovals;

    @Convert(converter = JpaListConverter.class)
    @Column(name = "required_roles", columnDefinition = "TEXT")
    private List<String> requiredRoles;

    @Column(name = "opened_at")
    private LocalDateTime openedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}
