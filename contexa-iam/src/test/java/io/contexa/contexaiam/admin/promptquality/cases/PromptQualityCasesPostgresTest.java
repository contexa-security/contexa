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
package io.contexa.contexaiam.admin.promptquality.cases;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacommon.security.UserAccountDeletedEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.quality.QualityAction;
import io.contexa.contexacore.std.components.prompt.quality.QualityActionBasis;
import io.contexa.contexacore.std.components.prompt.quality.QualityAnswer;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseClass;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseDocuments;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseKind;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseOrigin;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseRationale;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.std.components.prompt.quality.QualityScore;
import io.contexa.contexacore.std.components.prompt.quality.QualityScorer;
import io.contexa.contexacore.verification.evidence.SealedDecisionBaselines;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayInputs;
import io.contexa.contexaiam.admin.promptquality.evidence.JdbcSealedEvidencePackageRepository;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Quality plan 3.2, 3.7, 3.9 on a database with the schema of a new installation: the labelled cases are kept apart
 * from the sealed decisions, by scope; a case promoted from a sealed decision carries its sealed input and baselines
 * and names the package, which the retention then keeps; the default set is read only and changed by copying; an
 * answer is set by two people, and each change of it is kept; a published set fixes its cases by their content hashes
 * and leaves out the cases that wait; deleting a case, or its person, removes what holds the person's data.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class PromptQualityCasesPostgresTest {

    private static final String PROMPT = SecurityDecisionPromptDocument.PROMPT;
    private static final String SCOPE = "platform";
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;
    /** Three cases of the default set stand for it, so that each test reads little. */
    private static QualityCaseSet shipped;
    private static QualityCase threat;

    private final List<String> audited = new CopyOnWriteArrayList<>();
    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-11-22T09:00:00Z"));
    private PromptQualityCases cases;

    @BeforeAll
    static void aDatabaseWithTheSchema() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        try (Connection connection = database.dataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.setEscapeProcessing(false);
            statement.execute(schema);
        }
        QualityCaseSet all = QualityCaseSetReader.contexaDefault();
        shipped = new QualityCaseSet(all.name(), all.cases().subList(0, 3));
        threat = shipped.cases().stream().filter(QualityCase::shouldStop).findFirst().orElseThrow();
    }

    @AfterAll
    static void close() {
        if (database != null) {
            database.close();
        }
    }

    @BeforeEach
    void noCases() {
        jdbc.execute("TRUNCATE ctxa_prompt_version_case_cause, ctxa_prompt_version_measure_prompt,"
                + " ctxa_prompt_version_measure_answer, ctxa_prompt_version_measure, ctxa_prompt_version_case_set_member,"
                + " ctxa_prompt_version_case_set, ctxa_prompt_version_case_change, ctxa_prompt_version_case,"
                + " ctxa_sealed_evidence_package CASCADE");
        cases = store(true);
    }

    private PromptQualityCases store(boolean twoPerson) {
        Clock clock = new Clock() {
            @Override
            public ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return now.get();
            }
        };
        PromptVersionAudit audit = (action, scope, prompt, version, actor, detail) ->
                audited.add(action + " " + scope + " " + version + " " + actor);
        return new PromptQualityCases(() -> jdbc, JSON, twoPerson, audit, clock, null, () -> shipped);
    }

    private static QualityCaseExpectation answer(QualityCaseClass classification, QualityAction... allowed) {
        return new QualityCaseExpectation(EnumSet.of(allowed[0], allowed), null, classification,
                classification == QualityCaseClass.NORMAL ? QualityCaseKind.NORMAL_WORK : QualityCaseKind.OUTSIDER,
                new QualityCaseRationale("정답인 까닭", "Why it is the answer"), List.of());
    }

    /** The default case as the sealed package it stands for, with its baselines sealed beside the decision. */
    private static SealedEvidencePackage sealedOf(QualityCase item, String packageId, String userId) {
        SealedEvidencePackage sealed = QualityCaseSealedForm.sealed(item);
        sealed.setPackageId(packageId);
        sealed.setUserId(userId);
        ObjectNode facts = (ObjectNode) item.input().requestFacts().deepCopy();
        facts.put("userId", userId);
        sealed.setRequestFactsJson(facts.toString());
        ObjectNode snapshot = item.input().baselineSnapshot().isObject()
                ? (ObjectNode) item.input().baselineSnapshot().deepCopy() : JSON.createObjectNode();
        snapshot.remove(SealedDecisionBaselines.KEY);
        sealed.setBaselineSnapshotJson(snapshot.toString());
        return sealed;
    }

    @Test
    void aSealedDecisionIsPromotedWithItsSealedInputAndWaitsForAnotherAdministrator() {
        SealedEvidencePackage sealed = sealedOf(threat, "package-1", "alice");
        ObjectNode personal = JSON.createObjectNode().put("userId", "alice").put("updateCount", 12);

        // The company's time zone, which the engine draws the decision in, differs from the system's here.
        ZoneId company = ZoneId.of("Pacific/Chatham").equals(ZoneId.systemDefault())
                ? ZoneId.of("America/Sao_Paulo") : ZoneId.of("Pacific/Chatham");
        PromptQualityCases.Kept kept;
        EventTimeZone.set(company);
        try {
            kept = cases.promote(SCOPE, PROMPT, sealed, personal, null,
                    answer(QualityCaseClass.THREAT, QualityAction.BLOCK, QualityAction.CHALLENGE),
                    QualityCaseGrade.ORDINARY, "admin-a");
        }
        finally {
            EventTimeZone.set(null);
        }

        assertThat(kept.key()).startsWith("operation-");
        assertThat(kept.status()).isEqualTo(PromptQualityCases.PENDING);
        assertThat(kept.sealedPackageId()).isEqualTo("package-1");
        assertThat(kept.subjectUserId()).isEqualTo("alice");
        assertThat(kept.item().origin()).isEqualTo(QualityCaseOrigin.OPERATION);
        assertThat(kept.item().addedAt()).isEqualTo(now.get());
        assertThat(kept.item().environment().contextFormatVersion())
                .isEqualTo(SealedDecisionReplayInputs.CONTEXT_FORMAT_VERSION);
        assertThat(kept.item().environment().timeZone()).isEqualTo(company.getId());
        QualityCaseInput input = kept.item().input();
        assertThat(input.canonicalContext()).isEqualTo(threat.input().canonicalContext());
        assertThat(input.ragResults()).isEqualTo(threat.input().ragResults());
        assertThat(input.pastDeniedDecisions()).isEqualTo(threat.input().pastDeniedDecisions());
        assertThat(input.personalBaseline()).isEqualTo(personal);
        assertThat(input.organizationBaseline()).isNull();
        // What was kept reads back as the same case, and its sealed form is the same input again.
        assertThat(cases.kept(SCOPE, PROMPT, kept.key()).orElseThrow().item().contentHash())
                .isEqualTo(kept.item().contentHash());
        assertThat(QualityCaseSealedForm.input(QualityCaseSealedForm.sealed(kept.item()), input.personalBaseline(),
                null, JSON)).isEqualTo(input);
        // Nothing of the case is a sealed decision.
        assertThat(jdbc.queryForObject("select count(*) from ctxa_sealed_evidence_package", Integer.class)).isZero();
        assertThat(audited).containsExactly(PromptVersionAudit.CASE_SUBMITTED + " platform " + kept.key() + " admin-a");

        assertThatThrownBy(() -> cases.confirm(SCOPE, PROMPT, kept.key(), "admin-a"))
                .isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.SELF_CONFIRMATION));
        PromptQualityCases.Kept confirmed = cases.confirm(SCOPE, PROMPT, kept.key(), "admin-b");
        assertThat(confirmed.status()).isEqualTo(PromptQualityCases.CONFIRMED);
        assertThat(confirmed.confirmedBy()).isEqualTo("admin-b");
        assertThat(confirmed.confirmedAt()).isEqualTo(now.get());
        assertThat(audited).last().isEqualTo(PromptVersionAudit.CASE_CONFIRMED + " platform " + kept.key() + " admin-b");
        assertThatThrownBy(() -> cases.confirm(SCOPE, PROMPT, kept.key(), "admin-c"))
                .isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.ALREADY_CONFIRMED));
    }

    /** A package that sealed the baselines its decision read gives them to the case when none are given. */
    @Test
    void theBaselinesThePackageSealedAreTheCasesWhenNoneAreGiven() {
        SealedEvidencePackage sealed = sealedOf(threat, "package-2", "bob");
        ObjectNode snapshot = JSON.createObjectNode();
        ObjectNode kept = snapshot.putObject(SealedDecisionBaselines.KEY);
        kept.set("personal", JSON.createObjectNode().put("userId", "bob").put("updateCount", 3));
        // The organization's baseline was looked for and there was none.
        kept.putNull("organization");
        sealed.setBaselineSnapshotJson(snapshot.toString());

        PromptQualityCases.Kept promoted = cases.promote(SCOPE, PROMPT, sealed, null, null,
                answer(QualityCaseClass.THREAT, QualityAction.BLOCK), QualityCaseGrade.ORDINARY, "admin-a");

        assertThat(promoted.item().input().personalBaseline().path("updateCount").asInt()).isEqualTo(3);
        assertThat(promoted.item().input().organizationBaseline()).isNull();
    }

    @Test
    void aChangedAnswerIsKeptWithTheOneItReplacesAndWaitsAgain() {
        PromptQualityCases.Kept kept = cases.copy(SCOPE, PROMPT, threat.key(), null,
                answer(QualityCaseClass.THREAT, QualityAction.BLOCK), QualityCaseGrade.ORDINARY, "admin-a");
        cases.confirm(SCOPE, PROMPT, kept.key(), "admin-b");
        Instant changedAt = now.updateAndGet(at -> at.plus(Duration.ofHours(1)));
        QualityCaseExpectation normal = answer(QualityCaseClass.NORMAL, QualityAction.ALLOW);

        PromptQualityCases.Kept changed = cases.changeAnswer(SCOPE, PROMPT, kept.key(), normal,
                QualityCaseGrade.MUST_NOT_BLOCK, "admin-c");

        assertThat(changed.status()).isEqualTo(PromptQualityCases.PENDING);
        assertThat(changed.labelledBy()).isEqualTo("admin-c");
        assertThat(changed.confirmedBy()).isNull();
        assertThat(changed.item().expectation()).isEqualTo(normal);
        assertThat(changed.item().grade()).isEqualTo(QualityCaseGrade.MUST_NOT_BLOCK);
        // The input and the time the case came in stay; the content hash follows the answer.
        assertThat(changed.item().input()).isEqualTo(kept.item().input());
        assertThat(changed.item().addedAt()).isEqualTo(kept.item().addedAt());
        assertThat(changed.item().contentHash()).isNotEqualTo(kept.item().contentHash());
        List<PromptQualityCases.AnswerChange> history = cases.answerChanges(SCOPE, PROMPT, kept.key());
        assertThat(history).singleElement().satisfies(change -> {
            assertThat(change.changedBy()).isEqualTo("admin-c");
            assertThat(change.changedAt()).isEqualTo(changedAt);
            assertThat(change.previous()).isEqualTo(kept.item().expectation());
            assertThat(change.next()).isEqualTo(normal);
            assertThat(change.previousGrade()).isEqualTo(QualityCaseGrade.ORDINARY);
            assertThat(change.newGrade()).isEqualTo(QualityCaseGrade.MUST_NOT_BLOCK);
            assertThat(change.previousContentHash()).isEqualTo(kept.item().contentHash());
            assertThat(change.newContentHash()).isEqualTo(changed.item().contentHash());
        });
        assertThat(audited).contains(PromptVersionAudit.CASE_ANSWER_CHANGED + " platform " + kept.key() + " admin-c");
        // The one who changed it cannot confirm it; the one who first set it can.
        assertThatThrownBy(() -> cases.confirm(SCOPE, PROMPT, kept.key(), "admin-c"))
                .isInstanceOf(PromptQualityCases.RefusedException.class);
        assertThat(cases.confirm(SCOPE, PROMPT, kept.key(), "admin-a").confirmed()).isTrue();
        // The same answer again is no change.
        cases.changeAnswer(SCOPE, PROMPT, kept.key(), normal, QualityCaseGrade.MUST_NOT_BLOCK, "admin-d");
        assertThat(cases.answerChanges(SCOPE, PROMPT, kept.key())).hasSize(1);
        assertThat(cases.kept(SCOPE, PROMPT, kept.key()).orElseThrow().confirmed()).isTrue();
    }

    @Test
    void theDefaultSetIsReadOnlyAndChangedByCopyingIt() {
        assertThat(cases.find(SCOPE, PROMPT, threat.key())).contains(threat);
        assertThatThrownBy(() -> cases.changeAnswer(SCOPE, PROMPT, threat.key(),
                answer(QualityCaseClass.NORMAL, QualityAction.ALLOW), QualityCaseGrade.ORDINARY, "admin-a"))
                .isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.READ_ONLY));
        assertThatThrownBy(() -> cases.delete(SCOPE, PROMPT, threat.key(), "admin-a"))
                .isInstanceOf(PromptQualityCases.RefusedException.class);
        // A copy with other values is a case of the customer under the root of the original.
        ObjectNode facts = (ObjectNode) threat.input().requestFacts().deepCopy();
        facts.put("clientIp", "203.0.113.77");
        QualityCaseInput changedInput = new QualityCaseInput(threat.input().canonicalContext(), facts,
                threat.input().authState(), threat.input().baselineSnapshot(), threat.input().ragResults(),
                threat.input().pastDeniedDecisions(), threat.input().personalBaseline(),
                threat.input().organizationBaseline());

        PromptQualityCases.Kept copy = cases.copy(SCOPE, PROMPT, threat.key(), changedInput,
                threat.expectation(), threat.grade(), "admin-a");
        PromptQualityCases.Kept copyOfCopy = cases.copy(SCOPE, PROMPT, copy.key(), null, threat.expectation(),
                threat.grade(), "admin-a");

        assertThat(copy.key()).startsWith("customer-");
        assertThat(copy.item().origin()).isEqualTo(QualityCaseOrigin.CUSTOMER);
        assertThat(copy.item().rootKey()).isEqualTo(threat.rootKey());
        assertThat(copyOfCopy.item().rootKey()).isEqualTo(threat.rootKey());
        assertThat(copy.item().input().requestFacts().path("clientIp").asText()).isEqualTo("203.0.113.77");
        assertThat(copy.item().environment()).isEqualTo(threat.environment());
        // The default set is never copied into the database.
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_case", Integer.class)).isEqualTo(2);
        assertThat(cases.defaultSet().cases()).hasSize(3);
    }

    @Test
    void aPublishedSetFixesTheConfirmedCasesByTheirContentHashes() {
        PromptQualityCases.Kept first = cases.copy(SCOPE, PROMPT, threat.key(), null,
                answer(QualityCaseClass.THREAT, QualityAction.BLOCK), QualityCaseGrade.ORDINARY, "admin-a");
        PromptQualityCases.Kept waiting = cases.copy(SCOPE, PROMPT, threat.key(), null,
                answer(QualityCaseClass.THREAT, QualityAction.CHALLENGE), QualityCaseGrade.ORDINARY, "admin-a");
        cases.confirm(SCOPE, PROMPT, first.key(), "admin-b");

        PromptQualityCases.PublishedSet published = cases.publish(SCOPE, PROMPT, "admin-b");

        List<QualityCase> expected = new ArrayList<>(shipped.cases());
        expected.add(cases.kept(SCOPE, PROMPT, first.key()).orElseThrow().item());
        assertThat(published.version()).isEqualTo(new QualityCaseSet("any", expected).version());
        assertThat(published.caseCount()).isEqualTo(4);
        assertThat(published.defaultCaseCount()).isEqualTo(3);
        assertThat(published.defaultSetVersion()).isEqualTo(shipped.version());
        assertThat(audited).last().isEqualTo(PromptVersionAudit.CASE_SET_PUBLISHED + " platform " + published.version()
                + " admin-b");
        PromptQualityCases.ReadSet read = cases.read(published);
        assertThat(read.missing()).isEmpty();
        assertThat(read.cases().version()).isEqualTo(published.version());
        assertThat(read.cases().find(waiting.key())).isEmpty();
        // Publishing the same cases again is the same set.
        assertThat(cases.publish(SCOPE, PROMPT, "admin-c").id()).isEqualTo(published.id());

        // A later change of an answer does not change the set published before: it reads the answer it was
        // published with. The next publication holds the new answer once it is confirmed.
        cases.changeAnswer(SCOPE, PROMPT, first.key(), answer(QualityCaseClass.THREAT, QualityAction.CHALLENGE),
                QualityCaseGrade.ORDINARY, "admin-c");
        assertThat(cases.read(published).cases().version()).isEqualTo(published.version());
        assertThat(cases.publish(SCOPE, PROMPT, "admin-c").caseCount()).isEqualTo(3);
        cases.confirm(SCOPE, PROMPT, first.key(), "admin-a");
        cases.confirm(SCOPE, PROMPT, waiting.key(), "admin-b");
        PromptQualityCases.PublishedSet next = cases.publish(SCOPE, PROMPT, "admin-b");
        assertThat(next.caseCount()).isEqualTo(5);
        assertThat(next.version()).isNotEqualTo(published.version());
        assertThat(cases.latestPublished(SCOPE, PROMPT)).map(PromptQualityCases.PublishedSet::id).contains(next.id());
        assertThat(cases.read(published).cases().find(first.key()).orElseThrow().expectation().allowedActions())
                .containsExactly(QualityAction.BLOCK);
    }

    @Test
    void casesSetsAndPublicationsBelongToTheirScope() {
        PromptQualityCases.Kept other = cases.copy("tenant-b", PROMPT, threat.key(), null, threat.expectation(),
                threat.grade(), "admin-a");
        cases.confirm("tenant-b", PROMPT, other.key(), "admin-b");

        assertThat(cases.list(SCOPE, PROMPT)).isEmpty();
        assertThat(cases.kept(SCOPE, PROMPT, other.key())).isEmpty();
        assertThat(cases.publish(SCOPE, PROMPT, "admin-a").caseCount()).isEqualTo(3);
        assertThat(cases.publish("tenant-b", PROMPT, "admin-a").caseCount()).isEqualTo(4);
        assertThat(cases.latestPublished(SCOPE, PROMPT).orElseThrow().caseCount()).isEqualTo(3);
        assertThatThrownBy(() -> cases.publish(SCOPE, "cortex.other-prompt", "admin-a"))
                .isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.PROMPT));
    }

    @Test
    void withTwoPersonConfirmationOffACaseIsConfirmedAsItIsSubmitted() {
        PromptQualityCases single = store(false);
        PromptQualityCases.Kept kept = single.copy(SCOPE, PROMPT, threat.key(), null, threat.expectation(),
                threat.grade(), "admin-a");
        assertThat(kept.confirmed()).isTrue();
        assertThat(kept.confirmedBy()).isEqualTo("admin-a");
        PromptQualityCases.Kept changed = single.changeAnswer(SCOPE, PROMPT, kept.key(),
                answer(QualityCaseClass.THREAT, QualityAction.BLOCK), QualityCaseGrade.ORDINARY, "admin-a");
        assertThat(changed.confirmed()).isTrue();
        assertThat(single.answerChanges(SCOPE, PROMPT, kept.key())).hasSize(1);
        assertThat(single.publish(SCOPE, PROMPT, "admin-a").caseCount()).isEqualTo(4);
    }

    @Test
    void deletingACaseOrItsPersonRemovesWhatHoldsThePersonsData() {
        PromptQualityCases.Kept alice = cases.promote(SCOPE, PROMPT, sealedOf(threat, "package-a", "alice"), null, null,
                threat.expectation(), threat.grade(), "admin-a");
        PromptQualityCases.Kept bob = cases.promote("tenant-b", PROMPT, sealedOf(threat, "package-b", "bob"), null,
                null, threat.expectation(), threat.grade(), "admin-a");
        PromptQualityCases.Kept aliceAgain = cases.promote("tenant-b", PROMPT, sealedOf(threat, "package-c", "alice"),
                null, null, threat.expectation(), threat.grade(), "admin-a");
        cases.confirm(SCOPE, PROMPT, alice.key(), "admin-b");
        PromptQualityCases.PublishedSet published = cases.publish(SCOPE, PROMPT, "admin-b");
        long measure = measurement(published);
        answerWithPrompts(measure, SCOPE, alice.key(), "system-hash", "user-hash-alice");
        answerWithPrompts(measure, SCOPE, threat.key(), "system-hash", "user-hash-default");
        jdbc.update("insert into ctxa_prompt_version_case_cause (registry_scope, prompt_key, measure_id, case_key,"
                + " category, classified_by, classified_at) values (?, ?, ?, ?, 'JUDGEMENT_ERROR', 'rule', ?)",
                SCOPE, PROMPT, measure, alice.key(), Timestamp.from(now.get()));

        QualityCaseUserDeletionListener listener = new QualityCaseUserDeletionListener(cases);
        listener.onAccountDeleted(new UserAccountDeletedEvent(7L, "alice"));

        assertThat(jdbc.queryForList("select case_key from ctxa_prompt_version_case", String.class))
                .containsExactly(bob.key());
        assertThat(cases.kept("tenant-b", PROMPT, aliceAgain.key())).isEmpty();
        assertThat(jdbc.queryForList("select case_key from ctxa_prompt_version_measure_answer", String.class))
                .containsExactly(threat.key());
        assertThat(jdbc.queryForList("select prompt_hash from ctxa_prompt_version_measure_prompt order by prompt_hash",
                String.class)).containsExactly("system-hash", "user-hash-default");
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_case_cause", Integer.class)).isZero();
        // The published set keeps the key and the hash of the deleted case, and reads it as missing.
        PromptQualityCases.ReadSet read = cases.read(published);
        assertThat(read.missing()).containsExactly(alice.key());
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_case_set_member where case_key = ?"
                + " and expectation is null and case_id is null", Integer.class, alice.key())).isEqualTo(1);

        assertThat(cases.delete("tenant-b", PROMPT, bob.key(), "admin-a")).isTrue();
        assertThat(cases.delete("tenant-b", PROMPT, bob.key(), "admin-a")).isFalse();
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_case", Integer.class)).isZero();
    }

    /** Quality plan 3.7: the retention leaves the sealed package a kept case names, until the case is gone. */
    @Test
    void theRetentionLeavesThePackageACaseWasPromotedFrom() {
        JdbcSealedEvidencePackageRepository packages = new JdbcSealedEvidencePackageRepository(jdbc);
        Instant at = now.get();
        seal("package-held", at.minus(Duration.ofDays(120)), at.minus(Duration.ofDays(30)));
        seal("package-free", at.minus(Duration.ofDays(120)), at.minus(Duration.ofDays(30)));
        PromptQualityCases.Kept kept = cases.promote(SCOPE, PROMPT, sealedOf(threat, "package-held", "carol"), null,
                null, threat.expectation(), threat.grade(), "admin-a");

        assertThat(packages.deleteByExpiresAtBefore(at)).isEqualTo(1);
        assertThat(jdbc.queryForList("select package_id from ctxa_sealed_evidence_package", String.class))
                .containsExactly("package-held");

        cases.delete(SCOPE, PROMPT, kept.key(), "admin-a");
        assertThat(packages.deleteByExpiresAtBefore(at)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from ctxa_sealed_evidence_package", Integer.class)).isZero();
    }

    /**
     * Quality plan 3.2: a case came in when it was submitted, so the scoring can tell the cases that came in after a
     * version was made; the cases of the default set came with the product and are never later than a version.
     */
    @Test
    void aCaseCameInWhenItWasSubmitted() {
        Instant versionMade = now.get();
        now.set(versionMade.plus(Duration.ofDays(2)));
        PromptQualityCases.Kept later = cases.copy(SCOPE, PROMPT, threat.key(), null, threat.expectation(),
                threat.grade(), "admin-a");
        cases.confirm(SCOPE, PROMPT, later.key(), "admin-b");
        QualityCaseSet set = cases.read(cases.publish(SCOPE, PROMPT, "admin-b")).cases();

        assertThat(set.cases().stream().filter(item -> item.origin() == QualityCaseOrigin.CONTEXA)
                .allMatch(item -> item.addedAt() == null)).isTrue();
        List<QualityAnswer> answers = new ArrayList<>();
        for (QualityCase item : set.cases()) {
            answers.add(new QualityAnswer(item.key(), 1, QualityAction.BLOCK, QualityAction.BLOCK, false, false, 0, 0,
                    null, null, false, null));
        }
        Map<Boolean, QualityScore> byArrival = QualityScorer.scoreByArrival(set.cases(), answers,
                QualityActionBasis.FIRST_ANSWER, versionMade);
        assertThat(byArrival.get(true).cases()).isEqualTo(1);
        assertThat(byArrival.get(false).cases()).isEqualTo(3);
    }

    @Test
    void aCaseThatCannotBeACaseIsRefused() {
        // A case that must be caught cannot have an answer that allows.
        assertThatThrownBy(() -> cases.copy(SCOPE, PROMPT, threat.key(), null,
                answer(QualityCaseClass.THREAT, QualityAction.ALLOW, QualityAction.BLOCK), QualityCaseGrade.MUST_CATCH,
                "admin-a"))
                .isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.INVALID));
        SealedEvidencePackage empty = new SealedEvidencePackage();
        empty.setPackageId("package-empty");
        assertThatThrownBy(() -> cases.promote(SCOPE, PROMPT, empty, null, null, threat.expectation(), threat.grade(),
                "admin-a"))
                .isInstanceOfSatisfying(PromptQualityCases.RefusedException.class,
                        refused -> assertThat(refused.refusal()).isEqualTo(PromptQualityCases.Refusal.INVALID));
        assertThat(jdbc.queryForObject("select count(*) from ctxa_prompt_version_case", Integer.class)).isZero();
        // The case document written for a kept case is the document the default set reads.
        assertThat(QualityCaseDocuments.read(QualityCaseDocuments.write(threat), QualityCaseOrigin.CONTEXA, null))
                .isEqualTo(threat);
    }

    private long measurement(PromptQualityCases.PublishedSet set) {
        return jdbc.queryForObject("insert into ctxa_prompt_version_measure (registry_scope, prompt_key, version_number,"
                + " version_content_hash, case_set_id, case_set_version, repeats, settings_hash, settings,"
                + " closing_rules, status, planned_answers, reusable_answers, expected_min_calls, expected_max_calls,"
                + " call_limit, created_by, created_at) values (?, ?, 1, 'version-hash', ?, ?, 1, 'settings', '{}',"
                + " 'rules', 'DONE', 1, 0, 1, 1, 0, 'admin', ?) returning id", Long.class, set.scope(), set.prompt(),
                set.id(), set.version(), Timestamp.from(now.get()));
    }

    private void answerWithPrompts(long measure, String scope, String caseKey, String systemHash, String userHash) {
        jdbc.update("insert into ctxa_prompt_version_measure_answer (measure_id, registry_scope, case_key,"
                + " case_content_hash, version_number, version_content_hash, settings_hash, run_number,"
                + " system_prompt_hash, user_prompt_hash, created_at) values (?, ?, ?, 'hash', 1, 'version-hash',"
                + " 'settings', 1, ?, ?, ?)", measure, scope, caseKey, systemHash, userHash, Timestamp.from(now.get()));
        for (String hash : List.of(systemHash, userHash)) {
            jdbc.update("insert into ctxa_prompt_version_measure_prompt (registry_scope, prompt_hash, prompt_text,"
                    + " created_at) values (?, ?, ?, ?) on conflict do nothing", scope, hash, "prompt " + hash,
                    Timestamp.from(now.get()));
        }
    }

    private static void seal(String packageId, Instant capturedAt, Instant expiresAt) {
        jdbc.update("insert into ctxa_sealed_evidence_package (package_id, correlation_id, captured_at, package_hash,"
                + " expires_at) values (?, ?, ?, ?, ?)", packageId, "request-" + packageId, Timestamp.from(capturedAt),
                "hash", Timestamp.from(expiresAt));
    }
}
