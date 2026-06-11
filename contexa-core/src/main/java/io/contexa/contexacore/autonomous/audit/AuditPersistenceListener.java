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
package io.contexa.contexacore.autonomous.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;

/**
 * Async event listener that persists AuditRecord to database.
 * Decouples audit recording from business logic execution.
 */
@Slf4j
public class AuditPersistenceListener {

    private final CentralAuditFacade centralAuditFacade;

    public AuditPersistenceListener(CentralAuditFacade centralAuditFacade) {
        this.centralAuditFacade = centralAuditFacade;
    }

    @Async
    @EventListener
    public void onAuditRecordEvent(AuditRecordEvent event) {
        try {
            centralAuditFacade.persist(event.getAuditRecord());
        } catch (Exception e) {
            log.error("Failed to persist audit record asynchronously: category={}, principal={}",
                    event.getAuditRecord().getEventCategory(),
                    event.getAuditRecord().getPrincipalName(), e);
        }
    }
}
