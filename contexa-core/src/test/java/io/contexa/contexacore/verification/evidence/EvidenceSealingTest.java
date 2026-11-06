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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

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

    /** A sealed record's signature, its key's name or its hash taken away, after sealing began, is a change. */
    @Test
    void aDecisionRecordRobbedOfItsSealFailsOnceOlderSealedRecordsAreKept() {
        HmacEvidenceSigner signer = HmacEvidenceSigner.of(Map.of("k1", K1), null);
        for (Consumer<AuditLog> robbery : List.<Consumer<AuditLog>>of(
                record -> record.setRecordSignature(null),
                record -> record.setRecordSignature(" "),
                record -> record.setSignatureKeyId(null),
                record -> record.setSignatureKeyId(""),
                record -> {
                    record.setRecordSignature(null);
                    record.setSignatureKeyId(null);
                },
                record -> record.setRecordHash(null),
                record -> record.setRecordHash(" "),
                record -> {
                    record.setRecordHash(null);
                    record.setRecordSignature(null);
                    record.setSignatureKeyId(null);
                })) {
            AuditLog changed = record("ALLOW");
            DecisionRecordSeal.seal(changed, "previous-record-hash", signer);
            robbery.accept(changed);

            assertThat(DecisionRecordSeal.evaluate(changed, signer, hash -> true, olderKept -> true, older -> true))
                    .isEqualTo(Status.MISMATCH);
        }
    }

    /** A record from before sealing began carries none of it, and nothing older is sealed. */
    @Test
    void aDecisionRecordFromBeforeSealingStaysNotVerifiable() {
        HmacEvidenceSigner signer = HmacEvidenceSigner.of(Map.of("k1", K1), null);
        AuditLog legacy = record("ALLOW");

        assertThat(DecisionRecordSeal.evaluate(legacy, signer, hash -> true, nothingOlder -> false, nothingOlder -> false))
                .isEqualTo(Status.UNVERIFIABLE);
        assertThat(DecisionRecordSeal.evaluate(legacy, null, hash -> true, olderKept -> true, olderKept -> true))
                .as("no signer to tell").isEqualTo(Status.UNVERIFIABLE);
        assertThat(DecisionRecordSeal.evaluate(legacy, signer, hash -> true, null, null))
                .as("no store to ask").isEqualTo(Status.UNVERIFIABLE);
    }

    /** The record of a key never held, in the time the installation's key signs. */
    @ParameterizedTest
    @ValueSource(strings = {"forged-key", "K1", "ephemeral-1a2b3c4d"})
    void aDecisionRecordNamingAKeyNeverHeldFailsWhereTheKeysAreKept(String named) {
        HmacEvidenceSigner signer = HmacEvidenceSigner.of(Map.of("k1", K1), null);
        AuditLog record = record("ALLOW");
        DecisionRecordSeal.seal(record, "previous-record-hash", signer);
        record.setSignatureKeyId(named);

        assertThat(DecisionRecordSeal.evaluate(record, signer, hash -> true, older -> true, older -> true))
                .isEqualTo(Status.MISMATCH);
        assertThat(DecisionRecordSeal.evaluate(record, signer, hash -> true, older -> true, notYetInUse -> false))
                .as("from before the key came into use").isEqualTo(Status.UNVERIFIABLE);
        assertThat(DecisionRecordSeal.evaluate(record, HmacEvidenceSigner.of(Map.of(), null), hash -> true, older -> true,
                older -> true)).as("an ephemeral signer cannot tell").isEqualTo(Status.UNVERIFIABLE);
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

    /** Q-21 (PR-75): where the installation signs, a package without its signature was changed; it cannot just be unread. */
    @Test
    void aPackageWithoutItsSignatureFailsWhereTheInstallationSigns() {
        SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity(signer("k1", K1));
        SealedEvidencePackage pkg = pkg(SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION);
        integrity.seal(pkg, "previous-package-hash");

        pkg.setDecisionJson("{\"action\":\"ALLOW\"}");
        pkg.setPackageSignature(null);
        pkg.setSignatureKeyId(null);
        pkg.setPackageHash(integrity.computeHash(pkg));

        assertThat(integrity.evaluate(pkg)).isEqualTo(Status.MISMATCH);
    }

    /** Q-21: a signature made with a key the signer does not hold stays unread: a restart or a retired key gives that. */
    @Test
    void aSignatureOfAKeyNotHeldCannotBeVerifiedNorFailed() {
        SealedEvidencePackageIntegrity first = new SealedEvidencePackageIntegrity(signer("k1", K1));
        SealedEvidencePackage pkg = pkg(SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION);
        first.seal(pkg, null);

        assertThat(new SealedEvidencePackageIntegrity(signer("k2", K2)).evaluate(pkg)).isEqualTo(Status.UNVERIFIABLE);
    }

    /**
     * A key this installation never held, on a package from the time its key signs, is a forgery: the keys are
     * kept, so nothing else writes such a name. An attacker picks the name, so an ephemeral-looking one changes nothing.
     */
    @ParameterizedTest
    @ValueSource(strings = {"forged-key", "K1", "k1 x", "ephemeral-1a2b3c4d", "retired-2019", " "})
    void aSignatureNamingAKeyNeverHeldFailsWhereTheKeysAreKept(String named) {
        Instant keyInUseSince = Instant.parse("2026-10-24T04:00:00Z");
        SealedEvidencePackageIntegrity integrity = linked(new FakeChain(keyInUseSince, keyInUseSince));
        SealedEvidencePackage pkg = stored(integrity);
        pkg.setPackageSignature("0".repeat(64));
        pkg.setSignatureKeyId(named);

        assertThat(integrity.evaluate(pkg)).isEqualTo(Status.MISMATCH);
    }

    /** The cause says what to look at. */
    @Test
    void aKeyNeverHeldIsNamedAsTheCause() {
        Instant keyInUseSince = Instant.parse("2026-10-24T04:00:00Z");
        SealedEvidencePackageIntegrity integrity = linked(new FakeChain(keyInUseSince, keyInUseSince));
        SealedEvidencePackage pkg = stored(integrity);
        pkg.setSignatureKeyId("forged-key");

        assertThat(integrity.examine(pkg).cause()).isEqualTo(SealedEvidencePackageIntegrity.Cause.KEY_NOT_KNOWN);
    }

    /** Before the key came into use an ephemeral or retired key signed, and such a package stays unread. */
    @Test
    void aPackageFromBeforeTheKeyStaysNotVerifiable() {
        Instant keyInUseSince = NOW.plus(Duration.ofDays(1));
        SealedEvidencePackageIntegrity integrity = linked(new FakeChain(keyInUseSince, keyInUseSince));
        SealedEvidencePackage pkg = stored(integrity);
        pkg.setSignatureKeyId("ephemeral-1a2b3c4d");

        assertThat(integrity.evaluate(pkg)).isEqualTo(Status.UNVERIFIABLE);
    }

    /** An ephemeral key is lost with every restart, and each node has its own: an unknown key proves nothing there. */
    @Test
    void anEphemeralSignerStillCannotTellAnUnknownKey() {
        HmacEvidenceSigner ephemeral = HmacEvidenceSigner.of(Map.of(), null);
        SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity(ephemeral);
        integrity.setChain(new FakeChain(NOW.minusSeconds(60), NOW.minusSeconds(60)), KEPT_AT_LEAST,
                Clock.fixed(NOW, ZoneOffset.UTC));
        SealedEvidencePackage pkg = stored(integrity);
        pkg.setSignatureKeyId("ephemeral-1a2b3c4d");

        assertThat(ephemeral.keepsItsKeys()).isFalse();
        assertThat(HmacEvidenceSigner.of(Map.of("k1", K1), null).keepsItsKeys()).isTrue();
        assertThat(integrity.evaluate(pkg)).isEqualTo(Status.UNVERIFIABLE);
    }

    /** A signer of another kind does not say, and an unknown key stays what it was. */
    @Test
    void aSignerThatDoesNotSayKeepsAnUnknownKeyUnread() {
        EvidenceSigner other = new EvidenceSigner() {
            @Override
            public String activeKeyId() {
                return "hsm-1";
            }

            @Override
            public String sign(String value) {
                return "signed";
            }

            @Override
            public Boolean verify(String keyId, String value, String signature) {
                return null;
            }
        };
        SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity(other);
        integrity.setChain(new FakeChain(NOW.minusSeconds(60), NOW.minusSeconds(60)), KEPT_AT_LEAST,
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(integrity.evaluate(stored(integrity))).isEqualTo(Status.UNVERIFIABLE);
    }

    /** Lowering the schema skipped the signature, so any text in its two columns read as a verified package. */
    @ParameterizedTest
    @ValueSource(strings = {"k1", "forged-key", "ephemeral-1a2b3c4d"})
    void aLoweredPackageWithAnySignatureFails(String named) {
        Instant keyInUseSince = Instant.parse("2026-10-24T04:00:00Z");
        SealedEvidencePackageIntegrity integrity = linked(new FakeChain(keyInUseSince, keyInUseSince));
        for (int schema : new int[]{2, 1}) {
            SealedEvidencePackage lowered = pkg(schema);
            lowered.setPackageHash(integrity.computeHash(lowered));
            lowered.setPackageSignature("0".repeat(64));
            lowered.setSignatureKeyId(named);

            assertThat(integrity.evaluate(lowered)).as("schema " + schema + " with key " + named)
                    .isEqualTo(Status.MISMATCH);
        }
    }

    /** Q-21 (PR-75): measured, a decision changed and its schema lowered read as fully verified with no key at all. */
    @Test
    void aPackageLoweredToAnOlderSchemaAfterSigningBeganFails() {
        Instant signedSince = Instant.parse("2026-10-24T04:00:00Z");
        SealedEvidencePackageIntegrity integrity = linked(new FakeChain(signedSince));
        for (int schema : new int[]{2, 1}) {
            SealedEvidencePackage lowered = pkg(schema);
            lowered.setPackageHash(integrity.computeHash(lowered));

            assertThat(integrity.evaluate(lowered)).as("schema " + schema).isEqualTo(Status.MISMATCH);
        }
    }

    /** Q-21: a package captured before the first signed one was sealed without a key, as its schema says. */
    @Test
    void aPackageCapturedBeforeSigningBeganStaysVerified() {
        SealedEvidencePackageIntegrity integrity = linked(new FakeChain(Instant.parse("2026-10-24T06:00:00Z")));
        SealedEvidencePackage past = pkg(2);
        past.setPackageHash(integrity.computeHash(past));

        assertThat(integrity.evaluate(past)).isEqualTo(Status.VERIFIED);
        assertThat(linked(new FakeChain(null)).evaluate(past)).as("nothing signed yet").isEqualTo(Status.VERIFIED);
        past.setDecisionJson("{\"action\":\"ALLOW\"}");
        assertThat(integrity.evaluate(past)).as("its hash still holds it").isEqualTo(Status.MISMATCH);
    }

    /** Q-21: a blanked hash is no way out of the signature either. */
    @Test
    void aPackageWithoutItsHashesFailsWhereASignatureIsDue() {
        SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity(signer("k1", K1));
        SealedEvidencePackage blanked = pkg(SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION);
        integrity.seal(blanked, null);
        blanked.setPackageHash(" ");
        SealedEvidencePackage noPromptHash = pkg(SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION);
        integrity.seal(noPromptHash, null);
        noPromptHash.setRawUserPromptHash(null);
        noPromptHash.setPackageHash(integrity.computeHash(noPromptHash));

        assertThat(integrity.evaluate(blanked)).isEqualTo(Status.MISMATCH);
        assertThat(integrity.evaluate(noPromptHash)).isEqualTo(Status.MISMATCH);
        assertThat(new SealedEvidencePackageIntegrity().evaluate(blanked)).as("no signer").isEqualTo(Status.UNVERIFIABLE);
    }

    /** Q-21 (PR-76): measured, removing a package left the next one passing. */
    @Test
    void aPackageWhosePredecessorIsGoneInsideTheRetentionFails() {
        FakeChain chain = new FakeChain(null);
        chain.previousKept = false;
        chain.capturedBefore = NOW.minus(Duration.ofHours(1));
        SealedEvidencePackageIntegrity integrity = linked(chain);

        assertThat(integrity.evaluate(stored(integrity))).isEqualTo(Status.MISMATCH);
    }

    @Test
    void aPackageWhosePredecessorIsKeptPasses() {
        SealedEvidencePackageIntegrity integrity = linked(new FakeChain(null));

        assertThat(integrity.evaluate(stored(integrity))).isEqualTo(Status.VERIFIED);
    }

    /**
     * Q-21: the retention removes packages from inside the chain too: a clean package goes after the clean period, one
     * with a finding stays. A predecessor that may have gone that way, or the retention's oldest edge, is no mismatch.
     */
    @Test
    void aPredecessorTheRetentionMayHaveRemovedIsNoMismatch() {
        FakeChain chain = new FakeChain(null);
        chain.previousKept = false;
        SealedEvidencePackageIntegrity integrity = linked(chain);
        SealedEvidencePackage pkg = stored(integrity);

        assertThat(integrity.evaluate(pkg)).as("nothing older is kept").isEqualTo(Status.VERIFIED);
        chain.capturedBefore = NOW.minus(KEPT_AT_LEAST).minus(Duration.ofHours(1));
        assertThat(integrity.evaluate(pkg)).as("older than the shortest retention").isEqualTo(Status.VERIFIED);
        chain.capturedBefore = NOW.minus(KEPT_AT_LEAST).plus(Duration.ofHours(1));
        assertThat(integrity.evaluate(pkg)).as("inside it").isEqualTo(Status.MISMATCH);
    }

    @Test
    void theFirstLinkedPackageNamesNoPredecessor() {
        FakeChain chain = new FakeChain(null);
        chain.previousKept = false;
        SealedEvidencePackageIntegrity integrity = linked(chain);
        SealedEvidencePackage first = pkg(SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION);
        first.setId(1L);
        integrity.seal(first, null);

        assertThat(integrity.evaluate(first)).isEqualTo(Status.VERIFIED);
    }

    /** Q-21: a store that does not answer says nothing about the package; a screen or an inspection goes on. */
    @Test
    void aChainThatCannotBeReadLeavesThePackageUnread() {
        FakeChain chain = new FakeChain(null);
        chain.failure = new IllegalStateException("store down");
        SealedEvidencePackageIntegrity integrity = linked(chain);

        assertThat(integrity.evaluate(stored(integrity))).isEqualTo(Status.UNVERIFIABLE);
    }

    private static final Instant NOW = Instant.parse("2026-11-05T00:00:00Z");
    private static final Duration KEPT_AT_LEAST = Duration.ofDays(30);

    private static HmacEvidenceSigner signer(String id, String key) {
        return HmacEvidenceSigner.of(Map.of(id, key), null);
    }

    private static SealedEvidencePackageIntegrity linked(SealedEvidenceChain chain) {
        SealedEvidencePackageIntegrity integrity = new SealedEvidencePackageIntegrity(signer("k1", K1));
        integrity.setChain(chain, KEPT_AT_LEAST, Clock.fixed(NOW, ZoneOffset.UTC));
        return integrity;
    }

    private static SealedEvidencePackage stored(SealedEvidencePackageIntegrity integrity) {
        SealedEvidencePackage pkg = pkg(SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION);
        pkg.setId(7L);
        integrity.seal(pkg, "previous-package-hash");
        return pkg;
    }

    /** What a store answers about the packages around a package. */
    private static final class FakeChain implements SealedEvidenceChain {

        private final Instant signedSince;
        private final Instant keyInUseSince;
        private boolean previousKept = true;
        private Instant capturedBefore;
        private RuntimeException failure;

        private FakeChain(Instant signedSince) {
            this(signedSince, null);
        }

        private FakeChain(Instant signedSince, Instant keyInUseSince) {
            this.signedSince = signedSince;
            this.keyInUseSince = keyInUseSince;
        }

        @Override
        public Optional<Instant> signedSince() {
            return Optional.ofNullable(signedSince);
        }

        @Override
        public Optional<Instant> signedSince(String keyId) {
            return Optional.ofNullable(keyInUseSince);
        }

        @Override
        public boolean previousKept(SealedEvidencePackage pkg) {
            if (failure != null) {
                throw failure;
            }
            return previousKept;
        }

        @Override
        public Optional<Instant> capturedBefore(SealedEvidencePackage pkg) {
            return Optional.ofNullable(capturedBefore);
        }
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
