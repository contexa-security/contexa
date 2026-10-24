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
package io.contexa.contexacore.verification.evidence;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacore.autonomous.audit.DecisionRecordSeal;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity.Status;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** docs/agent A5-6: keyed signatures and links over decision records and sealed evidence. */
class EvidenceSealingTest {

    private static final String K1 = Base64.getEncoder().encodeToString("k1-0123456789abcdef0123456789abcd".getBytes());
    private static final String K2 = Base64.getEncoder().encodeToString("k2-0123456789abcdef0123456789abcd".getBytes());

    @Test
    void theSignerSignsWithTheActiveKeyAndVerifiesWithTheKeyASignatureNames() {
        HmacEvidenceSigner first = HmacEvidenceSigner.of(Map.of("k1", K1), null);
        String signature = first.sign("hash-a");

        assertThat(first.activeKeyId()).isEqualTo("k1");
        assertThat(first.verify("k1", "hash-a", signature)).isTrue();
        assertThat(first.verify("k1", "hash-b", signature)).isFalse();
        assertThat(first.verify("k9", "hash-a", signature)).as("a key it does not hold").isNull();

        Map<String, String> rotated = new LinkedHashMap<>();
        rotated.put("k1", K1);
        rotated.put("k2", K2);
        HmacEvidenceSigner second = HmacEvidenceSigner.of(rotated, "k2");
        assertThat(second.activeKeyId()).isEqualTo("k2");
        assertThat(second.verify("k1", "hash-a", signature)).as("a record signed before the change").isTrue();
        assertThat(second.sign("hash-a")).isNotEqualTo(signature);

        assertThatThrownBy(() -> HmacEvidenceSigner.of(Map.of("short", Base64.getEncoder().encodeToString(
                "too-short".getBytes())), null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> HmacEvidenceSigner.of(rotated, null))
                .as("two keys need the active one named").isInstanceOf(IllegalArgumentException.class);
        assertThat(HmacEvidenceSigner.of(Map.of(), null).activeKeyId()).startsWith("ephemeral-");
    }

    @Test
    void aDecisionRecordShowsAChangeARehashARemovedPredecessorAndAnUnknownKey() {
        HmacEvidenceSigner signer = HmacEvidenceSigner.of(Map.of("k1", K1), null);
        AuditLog first = record("ALLOW");
        DecisionRecordSeal.seal(first, null, signer);
        AuditLog second = record("BLOCK");
        DecisionRecordSeal.seal(second, first.getRecordHash(), signer);
        Set<String> kept = Set.of(first.getRecordHash(), second.getRecordHash());

        assertThat(DecisionRecordSeal.evaluate(first, signer, kept::contains)).isEqualTo(Status.VERIFIED);
        assertThat(DecisionRecordSeal.evaluate(second, signer, kept::contains)).isEqualTo(Status.VERIFIED);
        assertThat(second.getTimestamp().getNano() % 1000).as("kept to the microsecond the store keeps").isZero();

        second.setDecision("ALLOW");
        assertThat(DecisionRecordSeal.evaluate(second, signer, kept::contains)).as("changed").isEqualTo(Status.MISMATCH);
        second.setRecordHash(DecisionRecordSeal.recordHash(second));
        assertThat(DecisionRecordSeal.evaluate(second, signer, hash -> true))
                .as("changed, its hash computed again").isEqualTo(Status.MISMATCH);

        AuditLog third = record("CHALLENGE");
        DecisionRecordSeal.seal(third, "removed-record-hash", signer);
        assertThat(DecisionRecordSeal.evaluate(third, signer, kept::contains))
                .as("the record before it was removed").isEqualTo(Status.MISMATCH);

        third.setTenantId("tenant-b");
        assertThat(DecisionRecordSeal.evaluate(third, signer, hash -> true)).as("tenant covered")
                .isEqualTo(Status.MISMATCH);

        AuditLog legacy = record("ALLOW");
        assertThat(DecisionRecordSeal.evaluate(legacy, signer, kept::contains)).isEqualTo(Status.UNVERIFIABLE);
        HmacEvidenceSigner restarted = HmacEvidenceSigner.of(Map.of("k2", K2), null);
        assertThat(DecisionRecordSeal.evaluate(first, restarted, kept::contains))
                .as("signed with a key no longer held").isEqualTo(Status.UNVERIFIABLE);
    }

    /**
     * docs/agent A5-6: the audit retention deletes the oldest records, so the oldest kept record names a predecessor
     * that is gone; that is no mismatch. A predecessor removed while an older sealed record is kept still is.
     */
    @Test
    void theRetentionsBoundaryIsNoMismatchButARemovalInsideTheChainIs() {
        HmacEvidenceSigner signer = HmacEvidenceSigner.of(Map.of("k1", K1), null);
        AuditLog first = record("ALLOW");
        DecisionRecordSeal.seal(first, null, signer);
        AuditLog second = record("BLOCK");
        DecisionRecordSeal.seal(second, first.getRecordHash(), signer);
        Set<String> afterRetention = Set.of(second.getRecordHash());

        assertThat(DecisionRecordSeal.evaluate(second, signer, afterRetention::contains, oldest -> false))
                .as("the oldest kept record").isEqualTo(Status.VERIFIED);
        assertThat(DecisionRecordSeal.evaluate(second, signer, afterRetention::contains, olderKept -> true))
                .as("a record removed inside the chain").isEqualTo(Status.MISMATCH);
        second.setDecision("ALLOW");
        assertThat(DecisionRecordSeal.evaluate(second, signer, afterRetention::contains, oldest -> false))
                .as("the boundary record changed").isEqualTo(Status.MISMATCH);
    }

    @Test
    void aSchemaThreePackageCoversItsTenantUserTimeAndPredecessorAndIsSigned() {
        HmacEvidenceSigner signer = HmacEvidenceSigner.of(Map.of("k1", K1), null);
        SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity(signer);
        SealedEvidencePackage pkg = pkg(SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION);

        integrity.seal(pkg, "previous-package-hash");

        assertThat(pkg.getPreviousPackageHash()).isEqualTo("previous-package-hash");
        assertThat(pkg.getSignatureKeyId()).isEqualTo("k1");
        assertThat(integrity.evaluate(pkg)).isEqualTo(Status.VERIFIED);
        pkg.setUserId("mallory");
        assertThat(integrity.evaluate(pkg)).as("user covered").isEqualTo(Status.MISMATCH);
        pkg.setPackageHash(integrity.computeHash(pkg));
        assertThat(integrity.evaluate(pkg)).as("rehashed without the key").isEqualTo(Status.MISMATCH);
        assertThat(new SealedEvidencePackageIntegrity().evaluate(pkg)).as("no signer to check it")
                .isEqualTo(Status.UNVERIFIABLE);

        SealedEvidencePackage older = pkg(2);
        older.setPackageHash(integrity.computeHash(older));
        integrity.seal(older, "ignored");
        assertThat(older.getPreviousPackageHash()).as("an older schema keeps its form").isNull();
        assertThat(integrity.evaluate(older)).isEqualTo(Status.VERIFIED);
    }

    /**
     * docs/agent CF-28: a store keeps the capture time to the microsecond (PostgreSQL), so a package captured with
     * nanoseconds is sealed with the time the store keeps and verifies when it is read back, as a decision record does.
     */
    @Test
    void aSchemaThreePackageCapturedWithNanosecondsVerifiesAsTheStoreKeepsIt() {
        SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity(
                HmacEvidenceSigner.of(Map.of("k1", K1), null));
        SealedEvidencePackage pkg = pkg(SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION);
        pkg.setCapturedAt(Instant.parse("2026-10-24T10:48:32.123456789Z"));

        integrity.seal(pkg, "previous-package-hash");
        pkg.setCapturedAt(pkg.getCapturedAt().truncatedTo(ChronoUnit.MICROS));

        assertThat(pkg.getCapturedAt()).isEqualTo(Instant.parse("2026-10-24T10:48:32.123456Z"));
        assertThat(integrity.evaluate(pkg)).isEqualTo(Status.VERIFIED);
    }

    private static AuditLog record(String decision) {
        return AuditLog.builder()
                .timestamp(LocalDateTime.of(2026, 10, 24, 5, 0, 0, 123_456_789))
                .tenantId("tenant-a")
                .principalName("alice")
                .resourceIdentifier("GB-500")
                .action("SECURITY_DECISION")
                .decision(decision)
                .eventCategory("SECURITY_DECISION")
                .agentId("report-agent")
                .requestContextHash("ctx")
                .build();
    }

    private static SealedEvidencePackage pkg(int schemaVersion) {
        return SealedEvidencePackage.builder()
                .packageId("pkg-" + schemaVersion)
                .correlationId("request-1")
                .tenantId("tenant-a")
                .userId("alice")
                .capturedAt(Instant.parse("2026-10-24T05:00:00Z"))
                .rawUserPrompt("prompt")
                .rawUserPromptHash("sha256:prompt")
                .decisionJson("{\"action\":\"BLOCK\"}")
                .schemaVersion(schemaVersion)
                .build();
    }
}
