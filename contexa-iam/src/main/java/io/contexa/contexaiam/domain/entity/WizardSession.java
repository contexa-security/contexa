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

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "WIZARD_SESSION")
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class WizardSession {

    @Id
    @Column(name = "session_id", length = 36)
    private String id;

    @Column(name = "context_data", nullable = false, columnDefinition = "TEXT")
    private String contextData;

    @Column(nullable = false)
    private String ownerUserId;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    public static WizardSession create(String id, String contextData, String ownerUserId, int expirationMinutes) {
        WizardSession session = new WizardSession();
        session.setId(id);
        session.setContextData(contextData);
        session.setOwnerUserId(ownerUserId);
        session.setCreatedAt(LocalDateTime.now());
        session.setExpiresAt(LocalDateTime.now().plusMinutes(expirationMinutes));
        return session;
    }
}