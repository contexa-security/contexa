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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacore.verification.evidence.EvidenceSigner;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity.Status;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.function.Predicate;

/**
 * The tamper evidence of a decision record (docs/agent A5-6, AG-8): the SHA-256 of its fields, its tenant, user and
 * time included, and of the record written before it, signed with a key the signature names. A changed record fails
 * the hash; a changed record whose hash was computed again fails the signature; a removed record breaks the link of the
 * one after it. A record signed with a key the signer no longer holds, or written before records were sealed, cannot be
 * verified, which is said apart from a mismatch.
 */
public final class DecisionRecordSeal {

    /** The version of the record fields the hash covers. */
    static final String RECORD_VERSION = "ctxa.decision-record.v1";

    private static final ObjectMapper JSON = new ObjectMapper();

    private DecisionRecordSeal() {
    }

    /**
     * Seals the record after the one written before it: its time is kept to the microsecond the store keeps, its hash
     * covers the previous record's hash, and the signer signs it.
     */
    public static void seal(AuditLog record, @Nullable String previousRecordHash, EvidenceSigner signer) {
        if (record.getTimestamp() != null) {
            record.setTimestamp(record.getTimestamp().truncatedTo(ChronoUnit.MICROS));
        }
        record.setPreviousRecordHash(previousRecordHash);
        record.setRecordHash(recordHash(record));
        record.setSignatureKeyId(signer.activeKeyId());
        record.setRecordSignature(signer.sign(record.getRecordHash()));
    }

    /**
     * Whether the record is as it was sealed. The link is checked with {@code recordExists}: the record it names as
     * the one before it must still be there.
     */
    public static Status evaluate(AuditLog record, @Nullable EvidenceSigner signer,
                                  @Nullable Predicate<String> recordExists) {
        return evaluate(record, signer, recordExists, null);
    }

    /**
     * As {@link #evaluate(AuditLog, EvidenceSigner, Predicate)}, telling a record removed from inside the chain from
     * the retention's boundary: the audit retention deletes the oldest records, so the oldest kept record names a
     * previous record that is gone. Its link is then not checked; a missing previous record while an older sealed
     * record is kept is a removal from inside the chain and a mismatch.
     *
     * @param olderSealedKept whether a sealed decision record older than the record is kept, or null to treat every
     *                        missing previous record as a mismatch
     */
    public static Status evaluate(AuditLog record, @Nullable EvidenceSigner signer,
                                  @Nullable Predicate<String> recordExists,
                                  @Nullable Predicate<AuditLog> olderSealedKept) {
        if (record == null || !StringUtils.hasText(record.getRecordHash())) {
            return Status.UNVERIFIABLE;
        }
        if (!record.getRecordHash().equals(recordHash(record))) {
            return Status.MISMATCH;
        }
        if (StringUtils.hasText(record.getPreviousRecordHash()) && recordExists != null
                && !recordExists.test(record.getPreviousRecordHash())
                && (olderSealedKept == null || olderSealedKept.test(record))) {
            return Status.MISMATCH;
        }
        if (signer == null || !StringUtils.hasText(record.getRecordSignature())
                || !StringUtils.hasText(record.getSignatureKeyId())) {
            return Status.UNVERIFIABLE;
        }
        Boolean valid = signer.verify(record.getSignatureKeyId(), record.getRecordHash(), record.getRecordSignature());
        if (valid == null) {
            return Status.UNVERIFIABLE;
        }
        return valid ? Status.VERIFIED : Status.MISMATCH;
    }

    /** The SHA-256 (hex) of the record's fields and of the previous record's hash. */
    public static String recordHash(AuditLog record) {
        String[] fields = {
                RECORD_VERSION,
                record.getTenantId(),
                record.getPrincipalName(),
                record.getTimestamp() != null ? record.getTimestamp().toString() : null,
                record.getEventCategory(),
                record.getAction(),
                record.getDecision(),
                record.getReason(),
                record.getOutcome(),
                record.getRiskScore() != null ? record.getRiskScore().toString() : null,
                record.getResourceIdentifier(),
                record.getResourceUri(),
                record.getDetails(),
                record.getCorrelationId(),
                record.getSubjectKind(),
                record.getAgentId(),
                record.getDelegatorId(),
                record.getDelegationId(),
                record.getTargetAction(),
                record.getRiskState(),
                record.getEnforcementAction(),
                record.getEnforcementCause(),
                record.getRequestContextHash(),
                record.getPreviousRecordHash()
        };
        try {
            byte[] canonical = JSON.writeValueAsString(Arrays.asList(fields)).getBytes(StandardCharsets.UTF_8);
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical));
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("The decision record could not be hashed", e);
        }
    }
}
