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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;

import java.util.Map;
import io.contexa.contexacore.verification.evidence.EvidenceSigner;

/**
 * Central audit facade - single entry point for all audit log recording.
 * Supports both async (default) and sync modes.
 */
@Slf4j
public class CentralAuditFacade {

    private final AuditLogRepository auditLogRepository;
    private final ApplicationEventPublisher eventPublisher;
    /** docs/agent A5-6: the category whose records are sealed (the decision records). */
    static final String SEALED_CATEGORY = "SECURITY_DECISION";

    private final Object sealLock = new Object();
    private EvidenceSigner evidenceSigner;
    private final ObjectMapper objectMapper;

    public CentralAuditFacade(AuditLogRepository auditLogRepository,
                              ApplicationEventPublisher eventPublisher,
                              ObjectMapper objectMapper) {
        this.auditLogRepository = auditLogRepository;
        this.eventPublisher = eventPublisher;
        this.objectMapper = objectMapper.copy();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    /**
     * Record audit log asynchronously via Spring event.
     * Use this for non-critical paths (authentication, authorization) to avoid latency impact.
     */
    public void recordAsync(AuditRecord record) {
        try {
            eventPublisher.publishEvent(new AuditRecordEvent(this, record));
        } catch (Exception e) {
            log.error("Failed to publish audit event: category={}, principal={}",
                    record.getEventCategory(), record.getPrincipalName(), e);
            recordSyncFallback(record);
        }
    }

    /**
     * Record audit log synchronously.
     * Use this for critical paths (AI security decisions) where immediate persistence is required.
     */
    public void recordSync(AuditRecord record) {
        try {
            String detailsJson = toJsonString(record.getDetails());
            AuditLog auditLog = record.toAuditLog(detailsJson);
            save(auditLog);
        } catch (Exception e) {
            log.error("Failed to persist audit log synchronously: category={}, principal={}",
                    record.getEventCategory(), record.getPrincipalName(), e);
        }
    }

    /**
     * Persist an AuditRecord directly (used by AuditPersistenceListener).
     */
    void persist(AuditRecord record) {
        String detailsJson = toJsonString(record.getDetails());
        AuditLog auditLog = record.toAuditLog(detailsJson);
        save(auditLog);
    }

    /**
     * docs/agent A5-6: the signer decision records are sealed with; without one they are saved as before and read as
     * not verifiable.
     */
    public void setEvidenceSigner(EvidenceSigner evidenceSigner) {
        this.evidenceSigner = evidenceSigner;
    }

    /**
     * Saves the record; a decision record is sealed after the decision record saved before it (docs/agent A5-6). The
     * records this facade saves are linked in the order it saves them.
     */
    private void save(AuditLog auditLog) {
        if (evidenceSigner == null || !SEALED_CATEGORY.equals(auditLog.getEventCategory())) {
            auditLogRepository.save(auditLog);
            return;
        }
        synchronized (sealLock) {
            String previous = auditLogRepository
                    .findTopByEventCategoryAndRecordHashIsNotNullOrderByIdDesc(SEALED_CATEGORY)
                    .map(AuditLog::getRecordHash)
                    .orElse(null);
            DecisionRecordSeal.seal(auditLog, previous, evidenceSigner);
            auditLogRepository.save(auditLog);
        }
    }

    private void recordSyncFallback(AuditRecord record) {
        try {
            String detailsJson = toJsonString(record.getDetails());
            AuditLog auditLog = record.toAuditLog(detailsJson);
            save(auditLog);
        } catch (Exception e) {
            log.error("Sync fallback also failed for audit: category={}, principal={}",
                    record.getEventCategory(), record.getPrincipalName(), e);
        }
    }

    private String toJsonString(Map<String, Object> details) {
        if (details == null || details.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(details);
        } catch (Exception e) {
            log.error("Failed to serialize audit details to JSON", e);
            return details.toString();
        }
    }
}
