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
package io.contexa.contexaiam.admin.web.monitoring.service;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.audit.DecisionRecordSeal;
import io.contexa.contexacore.verification.evidence.EvidenceSigner;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity.Status;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import java.util.function.Supplier;

/**
 * docs/agent A5-6: whether a decision record is as it was sealed (VERIFIED, MISMATCH or UNVERIFIABLE), checked one way
 * for the security event log and for the dashboard's count of broken seals (N7). The oldest kept record names a previous
 * record the audit retention deleted, which is no mismatch; a record that lost its seal, or names a key the signer never
 * held, while older records are sealed is one. A check that fails reads as not verifiable.
 */
@Slf4j
public class DecisionRecordSealCheck {

    /** The category of the records that are sealed. */
    public static final String SEALED_CATEGORY = "SECURITY_DECISION";

    private final AuditLogRepository auditLogRepository;
    private final Supplier<EvidenceSigner> signer;

    /**
     * @param auditLogRepository the store the records are in; without one no record can be verified
     * @param signer             the signer the records were signed with, read at each check; null when there is none
     */
    public DecisionRecordSealCheck(@Nullable AuditLogRepository auditLogRepository,
                                   @Nullable Supplier<EvidenceSigner> signer) {
        this.auditLogRepository = auditLogRepository;
        this.signer = signer != null ? signer : () -> null;
    }

    /** Whether the record is sealed: a decision record; any other record has no seal to check. */
    public static boolean sealed(@Nullable AuditLog record) {
        return record != null && record.getId() != null && SEALED_CATEGORY.equals(record.getEventCategory());
    }

    /** What the seal of the decision record says; at most three reads of the store. */
    public Status check(AuditLog record) {
        if (auditLogRepository == null) {
            return Status.UNVERIFIABLE;
        }
        EvidenceSigner evidenceSigner = signer.get();
        try {
            return DecisionRecordSeal.evaluate(record, evidenceSigner, auditLogRepository::existsByRecordHash,
                    kept -> auditLogRepository.existsByEventCategoryAndRecordHashIsNotNullAndIdLessThan(SEALED_CATEGORY,
                            kept.getId()),
                    kept -> evidenceSigner != null && auditLogRepository
                            .existsByEventCategoryAndSignatureKeyIdAndIdLessThan(SEALED_CATEGORY,
                                    evidenceSigner.activeKeyId(), kept.getId()));
        } catch (RuntimeException e) {
            log.error("Integrity check failed for audit log {}", record.getId(), e);
            return Status.UNVERIFIABLE;
        }
    }
}
