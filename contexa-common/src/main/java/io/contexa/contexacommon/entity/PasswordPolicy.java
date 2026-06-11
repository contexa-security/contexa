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

import java.time.LocalDateTime;

@Entity
@Table(name = "password_policy")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PasswordPolicy {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    @Builder.Default
    private int minLength = 8;

    @Column(nullable = false)
    @Builder.Default
    private int maxLength = 128;

    @Builder.Default
    private boolean requireUppercase = true;

    @Builder.Default
    private boolean requireLowercase = true;

    @Builder.Default
    private boolean requireDigit = true;

    @Builder.Default
    private boolean requireSpecialChar = false;

    @Builder.Default
    private int maxFailedAttempts = 5;

    @Builder.Default
    private int lockoutDurationMinutes = 30;

    /** IP-level threshold (0 disables IP-based throttling). */
    @Builder.Default
    private int ipMaxFailedAttempts = 30;

    /** Time window (minutes) used to count IP-level failed attempts. */
    @Builder.Default
    private int ipWindowMinutes = 15;

    @Builder.Default
    private int passwordExpiryDays = 90;

    @Builder.Default
    private int historyCount = 3;

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
