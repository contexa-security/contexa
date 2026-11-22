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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseDocuments;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseEnvironment;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseInput;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseOrigin;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSet;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseSetReader;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayInputs;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionAudit;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.Nullable;
import org.springframework.transaction.support.TransactionOperations;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The labelled cases of the prompt quality measurement and their published sets (quality plan 3.2, 3.9), by the scope
 * of the prompt versions. The default set Contexa ships is read from the product and is read only: a case of it is
 * changed by copying it, the copy naming it as its root. The cases an administrator promotes from a sealed decision
 * or copies from another case are kept here, apart from the sealed decisions, each with who submitted it and who set
 * its answer. With two-person confirmation on (the default), a case and every change of its answer wait until another
 * administrator confirms them; only confirmed cases enter a published set. Every change of an answer is kept, with what
 * it was. A published set fixes its cases by their content hashes, so a measurement taken with it stays what it was
 * when cases are added. A case holds a person's data: deleting the case, or the person, removes it with the answers
 * measured on it and the prompts drawn from it.
 */
public class PromptQualityCases {

    private static final Logger log = LoggerFactory.getLogger(PromptQualityCases.class);

    /** A case whose answer waits for another administrator. */
    public static final String PENDING = "PENDING_CONFIRMATION";
    /** A case whose answer another administrator confirmed, or that needs no confirmation. */
    public static final String CONFIRMED = "CONFIRMED";

    /** Why something cannot be done to a case. */
    public enum Refusal {
        /** Only the security decision has labelled cases. */
        PROMPT,
        /** There is no such case. */
        NOT_FOUND,
        /** A case of the default set Contexa ships is read only: copy it to change it. */
        READ_ONLY,
        /** The administrator who set the answer cannot confirm it. */
        SELF_CONFIRMATION,
        /** The answer is confirmed already. */
        ALREADY_CONFIRMED,
        /** The case, its answer or its input is not one a case can have. */
        INVALID,
        /**
         * Quality plan 3.6: the decision is not sealed, so there is no input of it to make a case of (its evaluation
         * alone can be kept).
         */
        NOT_SEALED,
        /** Quality plan 3.6: the two versions of the trial did not decide the sealed decision differently. */
        NOT_DIVERGENT
    }

    /** What cannot be done, and why. */
    public static class RefusedException extends RuntimeException {

        private final Refusal refusal;

        public RefusedException(Refusal refusal, String message) {
            super(message);
            this.refusal = refusal;
        }

        public Refusal refusal() {
            return refusal;
        }
    }

    /**
     * A case kept here.
     *
     * @param item            the case, which came in when it was submitted
     * @param sealedPackageId the sealed package it was promoted from, or null
     * @param subjectUserId   whose decision its input is, or null
     * @param labelledBy      who set its present answer
     * @param secondAnalysis  quality plan 3.6: whether it was promoted from a decision the second analysis decided; the
     *                        package holds the second analysis's input, so the first pass replayed from it may read
     *                        another input than the decision's first pass did
     */
    public record Kept(long id, String scope, String prompt, QualityCase item, String status,
                       @Nullable String sealedPackageId, @Nullable String subjectUserId, String submittedBy,
                       Instant submittedAt, String labelledBy, Instant labelledAt, @Nullable String confirmedBy,
                       @Nullable Instant confirmedAt, boolean secondAnalysis) {

        public String key() {
            return item.key();
        }

        public boolean confirmed() {
            return CONFIRMED.equals(status);
        }
    }

    /**
     * Quality plan 3.6: the cases kept in a scope, counted apart by where they came from.
     *
     * @param kept           every case kept in the scope
     * @param operation      those promoted from a decision of the operation
     * @param secondAnalysis those promoted from a decision the second analysis decided, counted apart
     * @param pending        those whose answer waits for another administrator
     */
    public record Counts(int kept, int operation, int secondAnalysis, int pending) {
    }

    /** One change of a case's answer: what it was and what it became. */
    public record AnswerChange(long id, String caseKey, String changedBy, Instant changedAt,
                               QualityCaseGrade previousGrade, QualityCaseGrade newGrade,
                               QualityCaseExpectation previous, QualityCaseExpectation next,
                               String previousContentHash, String newContentHash) {
    }

    /** A published version of the case set. */
    public record PublishedSet(long id, String scope, String prompt, String version, String name, int caseCount,
                               @Nullable String defaultSetVersion, int defaultCaseCount, String publishedBy,
                               Instant publishedAt) {
    }

    /**
     * The cases of a published set as they can be read now, and the keys of those that cannot: a case deleted since,
     * or a case of the default set an upgrade of the product changed.
     */
    public record ReadSet(PublishedSet set, QualityCaseSet cases, List<String> missing) {
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final ObjectMapper json;
    private final boolean twoPersonConfirmation;
    private final PromptVersionAudit audit;
    private final Clock clock;
    private final TransactionOperations transactions;
    private final Supplier<QualityCaseSet> defaultSetSource;
    private volatile QualityCaseSet defaultSet;

    /**
     * @param twoPersonConfirmation whether a case and a change of its answer wait for another administrator; off for
     *                              an installation with one administrator
     * @param transactions          what runs a change of several rows as one, or none
     * @param defaultSet            the default set Contexa ships, read once when first needed
     */
    public PromptQualityCases(Supplier<JdbcTemplate> jdbc, ObjectMapper json, boolean twoPersonConfirmation,
                              @Nullable PromptVersionAudit audit, @Nullable Clock clock,
                              @Nullable TransactionOperations transactions,
                              @Nullable Supplier<QualityCaseSet> defaultSet) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.json = Objects.requireNonNull(json, "json");
        this.twoPersonConfirmation = twoPersonConfirmation;
        this.audit = audit != null ? audit : PromptVersionAudit.none();
        this.clock = clock != null ? clock : Clock.systemUTC();
        this.transactions = transactions != null ? transactions : TransactionOperations.withoutTransaction();
        this.defaultSetSource = defaultSet != null ? defaultSet : QualityCaseSetReader::contexaDefault;
    }

    /** Whether the prompt has labelled cases: only the security decision has decisions to measure (plan 3.4). */
    public static boolean offeredFor(String prompt) {
        return SecurityDecisionPromptDocument.PROMPT.equals(prompt);
    }

    public boolean twoPersonConfirmation() {
        return twoPersonConfirmation;
    }

    /** The default set Contexa ships with this build, the same in every scope. */
    public QualityCaseSet defaultSet() {
        QualityCaseSet set = defaultSet;
        if (set == null) {
            synchronized (this) {
                set = defaultSet;
                if (set == null) {
                    set = Objects.requireNonNull(defaultSetSource.get(), "default set");
                    defaultSet = set;
                }
            }
        }
        return set;
    }

    // ----- the cases -----

    /** The case of the key: one of the default set, or one kept in the scope. */
    public Optional<QualityCase> find(String scope, String prompt, String key) {
        if (!offeredFor(prompt) || key == null) {
            return Optional.empty();
        }
        Optional<QualityCase> shipped = defaultSet().find(key.trim());
        return shipped.isPresent() ? shipped : kept(scope, prompt, key).map(Kept::item);
    }

    public Optional<Kept> kept(String scope, String prompt, String key) {
        if (key == null) {
            return Optional.empty();
        }
        return jdbc.get().query(CASE_SQL + " where registry_scope = ? and prompt_key = ? and case_key = ?", this::kept,
                scopeOf(scope), prompt, key.trim()).stream().findFirst();
    }

    /** The cases kept in the scope, the oldest first. */
    public List<Kept> list(String scope, String prompt) {
        return jdbc.get().query(CASE_SQL + " where registry_scope = ? and prompt_key = ? order by id", this::kept,
                scopeOf(scope), prompt);
    }

    /**
     * Quality plan 3.2: a sealed decision as a case of the operation, with the answer the administrator gives. Its
     * input is the package's sealed sections with the baselines given, else those the package sealed with its
     * decision; it names the package, which is then kept past its retention for as long as the case is.
     *
     * @throws RefusedException when the prompt has no cases, or the package or the answer cannot make a case
     */
    public Kept promote(String scope, String prompt, SealedEvidencePackage sealed, @Nullable JsonNode userBaseline,
                        @Nullable JsonNode organizationBaseline, QualityCaseExpectation expectation,
                        QualityCaseGrade grade, String actor) {
        Objects.requireNonNull(sealed, "sealed");
        QualityCaseInput input;
        try {
            input = QualityCaseSealedForm.input(sealed, userBaseline, organizationBaseline, json);
        }
        catch (IllegalArgumentException unreadable) {
            throw new RefusedException(Refusal.INVALID, unreadable.getMessage());
        }
        String subject = QualityCaseSealedForm.subject(input);
        // The decision was drawn in the time zone of the server that made it, and with the context format it reads.
        QualityCaseEnvironment environment = new QualityCaseEnvironment(ZoneId.systemDefault().getId(),
                SealedDecisionReplayInputs.CONTEXT_FORMAT_VERSION);
        return insert(scope, prompt, QualityCaseOrigin.OPERATION, input, expectation, grade, null, environment,
                sealed.getPackageId(), subject != null ? subject : sealed.getUserId(), actor,
                QualityCaseSealedForm.secondAnalysis(sealed, json));
    }

    /**
     * Quality plan 3.2: a case of the customer made from another case, of the default set or kept here, with the
     * input changed or as it is and an answer of its own; it names the source's root as its root, so it is counted
     * with its original. A case of the default set is changed this way, and only this way.
     *
     * @param input the input of the copy, or null for the source's
     * @throws RefusedException when there is no such source, or the copy cannot be a case
     */
    public Kept copy(String scope, String prompt, String sourceKey, @Nullable QualityCaseInput input,
                     QualityCaseExpectation expectation, QualityCaseGrade grade, String actor) {
        QualityCase source = find(scope, prompt, sourceKey).orElseThrow(() -> new RefusedException(Refusal.NOT_FOUND,
                "There is no case " + sourceKey));
        Optional<Kept> keptSource = kept(scope, prompt, source.key());
        QualityCaseInput copied = input != null ? input : source.input();
        String subject = QualityCaseSealedForm.subject(copied);
        if (subject == null && keptSource.isPresent()) {
            subject = keptSource.get().subjectUserId();
        }
        return insert(scope, prompt, QualityCaseOrigin.CUSTOMER, copied, expectation, grade, source.rootKey(),
                source.environment(), keptSource.map(Kept::sealedPackageId).orElse(null), subject, actor,
                keptSource.map(Kept::secondAnalysis).orElse(false));
    }

    /**
     * Quality plan 3.2: a new answer of a kept case. The change is kept with the answer it replaces; with two-person
     * confirmation the case waits again for an administrator other than the one who changed it. An answer the same
     * as the present one changes nothing.
     *
     * @throws RefusedException when the case is of the default set, or there is no such case, or the answer cannot
     *                          be the answer of the case
     */
    public Kept changeAnswer(String scope, String prompt, String key, QualityCaseExpectation expectation,
                             QualityCaseGrade grade, String actor) {
        if (defaultSet().find(key).isPresent()) {
            throw new RefusedException(Refusal.READ_ONLY, "The case " + key
                    + " is of the default set Contexa ships; copy it to change its answer");
        }
        Kept kept = kept(scope, prompt, key).orElseThrow(() -> new RefusedException(Refusal.NOT_FOUND,
                "There is no case " + key));
        QualityCase before = kept.item();
        QualityCase after = caseOf(before.key(), before.input(), expectation, grade, before.rootCaseKey(),
                before.environment(), before.origin(), before.addedAt());
        String previousHash = before.contentHash();
        String newHash = after.contentHash();
        if (previousHash.equals(newHash)) {
            return kept;
        }
        Instant now = clock.instant();
        String who = actorOf(actor);
        transactions.executeWithoutResult(status -> {
            jdbc.get().update("insert into ctxa_prompt_version_case_change (registry_scope, case_id, case_key,"
                    + " changed_by, changed_at, previous_grade, new_grade, previous_expectation, new_expectation,"
                    + " previous_content_hash, new_content_hash) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    kept.scope(), kept.id(), kept.key(), who, Timestamp.from(now), before.grade().name(),
                    grade.name(), QualityCaseDocuments.writeExpectation(before.expectation()).toString(),
                    QualityCaseDocuments.writeExpectation(expectation).toString(), previousHash, newHash);
            jdbc.get().update("update ctxa_prompt_version_case set grade = ?, classification = ?, case_kind = ?,"
                    + " expectation = ?, content_hash = ?, labelled_by = ?, labelled_at = ?, status = ?,"
                    + " confirmed_by = ?, confirmed_at = ? where id = ?", grade.name(),
                    expectation.classification().name(), expectation.kind().name(),
                    QualityCaseDocuments.writeExpectation(expectation).toString(), newHash, who, Timestamp.from(now),
                    twoPersonConfirmation ? PENDING : CONFIRMED, twoPersonConfirmation ? null : who,
                    twoPersonConfirmation ? null : Timestamp.from(now), kept.id());
        });
        audit.record(PromptVersionAudit.CASE_ANSWER_CHANGED, kept.scope(), kept.prompt(), kept.key(), who,
                previousHash + " -> " + newHash);
        return kept(scope, prompt, key).orElseThrow();
    }

    /**
     * Quality plan 3.2: another administrator confirms the answer of a case, which may then enter a published set.
     *
     * @throws RefusedException when there is no such case, its answer is confirmed already, or the one confirming it
     *                          set it
     */
    public Kept confirm(String scope, String prompt, String key, String actor) {
        Kept kept = kept(scope, prompt, key).orElseThrow(() -> new RefusedException(Refusal.NOT_FOUND,
                "There is no case " + key));
        if (kept.confirmed()) {
            throw new RefusedException(Refusal.ALREADY_CONFIRMED, "The answer of the case " + key
                    + " is confirmed already");
        }
        String who = actorOf(actor);
        if (who.equals(kept.labelledBy())) {
            throw new RefusedException(Refusal.SELF_CONFIRMATION, "The answer of the case " + key
                    + " is confirmed by an administrator other than the one who set it");
        }
        // The answer confirmed is the one read: an answer changed in the meantime is not confirmed with it.
        int updated = jdbc.get().update("update ctxa_prompt_version_case set status = ?, confirmed_by = ?,"
                + " confirmed_at = ? where id = ? and status = ? and content_hash = ?", CONFIRMED, who,
                Timestamp.from(clock.instant()), kept.id(), PENDING, kept.item().contentHash());
        if (updated != 1) {
            throw new RefusedException(Refusal.ALREADY_CONFIRMED, "The answer of the case " + key
                    + " changed or was confirmed meanwhile");
        }
        audit.record(PromptVersionAudit.CASE_CONFIRMED, kept.scope(), kept.prompt(), kept.key(), who,
                kept.item().contentHash());
        return kept(scope, prompt, key).orElseThrow();
    }

    /** Quality plan 3.6: the cases kept in the scope, with those promoted from the second analysis counted apart. */
    public Counts counts(String scope, String prompt) {
        return jdbc.get().queryForObject("select count(*), count(*) filter (where origin = ?), count(*) filter (where"
                + " second_analysis), count(*) filter (where status = ?) from ctxa_prompt_version_case where"
                + " registry_scope = ? and prompt_key = ?", (rs, row) -> new Counts(rs.getInt(1), rs.getInt(2),
                rs.getInt(3), rs.getInt(4)), QualityCaseOrigin.OPERATION.name(), PENDING, scopeOf(scope), prompt);
    }

    /** The changes of the case's answer, the oldest first. */
    public List<AnswerChange> answerChanges(String scope, String prompt, String key) {
        return jdbc.get().query("select h.id, h.case_key, h.changed_by, h.changed_at, h.previous_grade, h.new_grade,"
                + " h.previous_expectation, h.new_expectation, h.previous_content_hash, h.new_content_hash from"
                + " ctxa_prompt_version_case_change h join ctxa_prompt_version_case c on c.id = h.case_id where"
                + " c.registry_scope = ? and c.prompt_key = ? and c.case_key = ? order by h.changed_at, h.id",
                (rs, row) -> new AnswerChange(rs.getLong(1), rs.getString(2), rs.getString(3),
                        rs.getTimestamp(4).toInstant(), QualityCaseGrade.valueOf(rs.getString(5)),
                        QualityCaseGrade.valueOf(rs.getString(6)), expectation(rs.getString(7)),
                        expectation(rs.getString(8)), rs.getString(9), rs.getString(10)),
                scopeOf(scope), prompt, key);
    }

    /**
     * Quality plan 3.2: deletes a kept case with what holds its data: the changes of its answer, the answers measured
     * on it and the prompts drawn from it that nothing else names. A published set that held it keeps its key and
     * content hash, and reads it as missing. A case of the default set cannot be deleted.
     *
     * @return whether there was such a case
     */
    public boolean delete(String scope, String prompt, String key, String actor) {
        if (defaultSet().find(key).isPresent()) {
            throw new RefusedException(Refusal.READ_ONLY, "The case " + key + " is of the default set Contexa ships");
        }
        Optional<Kept> kept = kept(scope, prompt, key);
        kept.ifPresent(found -> {
            purge(List.of(found));
            log.info("[PromptQualityCase] Case {} of {} deleted by {}", found.key(), found.scope(), actorOf(actor));
        });
        return kept.isPresent();
    }

    /**
     * Quality plan 3.2: the deletion of a person reaches the cases whose decision is the person's, in every scope.
     *
     * @return how many cases were deleted
     */
    public int deleteSubject(String userId) {
        if (userId == null || userId.isBlank()) {
            return 0;
        }
        List<Kept> found = jdbc.get().query(CASE_SQL + " where subject_user_id = ? order by id", this::kept,
                userId.trim());
        if (!found.isEmpty()) {
            purge(found);
            log.info("[PromptQualityCase] {} cases of a deleted user removed", found.size());
        }
        return found.size();
    }

    private void purge(List<Kept> cases) {
        transactions.executeWithoutResult(status -> {
            for (Kept item : cases) {
                jdbc.get().update("delete from ctxa_prompt_version_measure_answer where registry_scope = ? and"
                        + " case_key = ?", item.scope(), item.key());
                jdbc.get().update("delete from ctxa_prompt_version_case_cause where registry_scope = ? and"
                        + " prompt_key = ? and case_key = ?", item.scope(), item.prompt(), item.key());
                jdbc.get().update("update ctxa_prompt_version_case_set_member set expectation = null where case_id = ?",
                        item.id());
                jdbc.get().update("delete from ctxa_prompt_version_case where id = ?", item.id());
            }
            for (String scope : cases.stream().map(Kept::scope).distinct().toList()) {
                jdbc.get().update("delete from ctxa_prompt_version_measure_prompt p where p.registry_scope = ? and not"
                        + " exists (select 1 from ctxa_prompt_version_measure_answer a where a.registry_scope ="
                        + " p.registry_scope and (a.system_prompt_hash = p.prompt_hash or a.user_prompt_hash ="
                        + " p.prompt_hash))", scope);
            }
        });
    }

    private Kept insert(String scope, String prompt, QualityCaseOrigin origin, QualityCaseInput input,
                        QualityCaseExpectation expectation, QualityCaseGrade grade, @Nullable String rootCaseKey,
                        QualityCaseEnvironment environment, @Nullable String sealedPackageId,
                        @Nullable String subject, String actor, boolean secondAnalysis) {
        if (!offeredFor(prompt)) {
            throw new RefusedException(Refusal.PROMPT, "Only the security decision has labelled cases");
        }
        Objects.requireNonNull(expectation, "expectation");
        Objects.requireNonNull(grade, "grade");
        String scopeName = scopeOf(scope);
        String who = actorOf(actor);
        Instant now = clock.instant();
        Long id = jdbc.get().queryForObject("select nextval(pg_get_serial_sequence('ctxa_prompt_version_case', 'id'))",
                Long.class);
        // The key is the origin and the row's number, so it never meets a key of the default set or another case.
        String key = origin.name().toLowerCase(Locale.ROOT) + "-" + Objects.requireNonNull(id, "id");
        QualityCase item = caseOf(key, input, expectation, grade, rootCaseKey, environment, origin, now);
        boolean confirmed = !twoPersonConfirmation;
        jdbc.get().update("insert into ctxa_prompt_version_case (id, registry_scope, prompt_key, case_key, origin,"
                + " root_case_key, sealed_package_id, subject_user_id, grade, classification, case_kind,"
                + " content_hash, case_input, expectation, time_zone, context_format_version, status,"
                + " submitted_by, submitted_at, labelled_by, labelled_at, confirmed_by, confirmed_at, second_analysis)"
                + " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", id, scopeName,
                prompt, key, origin.name(), item.rootCaseKey(), sealedPackageId, subject, grade.name(),
                expectation.classification().name(), expectation.kind().name(), item.contentHash(),
                QualityCaseDocuments.writeInput(input).toString(),
                QualityCaseDocuments.writeExpectation(expectation).toString(), environment.timeZone(),
                environment.contextFormatVersion(), confirmed ? CONFIRMED : PENDING, who, Timestamp.from(now), who,
                Timestamp.from(now), confirmed ? who : null, confirmed ? Timestamp.from(now) : null, secondAnalysis);
        audit.record(PromptVersionAudit.CASE_SUBMITTED, scopeName, prompt, key, who,
                origin.name() + (item.rootCaseKey() != null ? " from " + item.rootCaseKey() : "")
                        + (sealedPackageId != null ? " package " + sealedPackageId : "")
                        + (secondAnalysis ? " second analysis" : ""));
        return kept(scopeName, prompt, key).orElseThrow();
    }

    private static QualityCase caseOf(String key, QualityCaseInput input, QualityCaseExpectation expectation,
                                      QualityCaseGrade grade, @Nullable String rootCaseKey,
                                      QualityCaseEnvironment environment, QualityCaseOrigin origin, Instant addedAt) {
        try {
            return new QualityCase(key, input, expectation, grade, rootCaseKey, environment, origin, addedAt);
        }
        catch (IllegalArgumentException | NullPointerException invalid) {
            throw new RefusedException(Refusal.INVALID, invalid.getMessage());
        }
    }

    // ----- the published sets -----

    /**
     * Quality plan 3.2: publishes the case set of the scope: the default set of this build and the confirmed cases
     * kept in the scope, fixed by their content hashes. A case that waits for confirmation is not in it. The same
     * cases published again are the set published before.
     */
    public PublishedSet publish(String scope, String prompt, String actor) {
        return publish(scope, prompt, actor, true);
    }

    /**
     * Quality plan 3.4: publishes the default set of this build alone in the scope, as the automatic measurement does
     * when nothing is published there yet: the cases kept in the scope are not in it. The same set published again is
     * the set published before.
     */
    public PublishedSet publishDefault(String scope, String prompt, String actor) {
        return publish(scope, prompt, actor, false);
    }

    private PublishedSet publish(String scope, String prompt, String actor, boolean withKeptCases) {
        if (!offeredFor(prompt)) {
            throw new RefusedException(Refusal.PROMPT, "Only the security decision has labelled cases");
        }
        String scopeName = scopeOf(scope);
        QualityCaseSet shipped = defaultSet();
        List<Kept> confirmed = withKeptCases
                ? list(scopeName, prompt).stream().filter(Kept::confirmed).toList() : List.of();
        List<QualityCase> cases = new ArrayList<>(shipped.cases());
        confirmed.forEach(kept -> cases.add(kept.item()));
        QualityCaseSet set = new QualityCaseSet(shipped.name(), cases);
        String version = set.version();
        Optional<PublishedSet> existing = published(scopeName, prompt, version);
        if (existing.isPresent()) {
            return existing.get();
        }
        String who = actorOf(actor);
        Instant now = clock.instant();
        transactions.executeWithoutResult(status -> {
            jdbc.get().update("insert into ctxa_prompt_version_case_set (registry_scope, prompt_key, set_version, name,"
                    + " case_count, default_set_version, default_case_count, published_by, published_at) values"
                    + " (?, ?, ?, ?, ?, ?, ?, ?, ?) on conflict (registry_scope, prompt_key, set_version) do nothing",
                    scopeName, prompt, version, set.name(), cases.size(), shipped.version(), shipped.cases().size(),
                    who, Timestamp.from(now));
            Long setId = jdbc.get().queryForObject("select id from ctxa_prompt_version_case_set where registry_scope = ?"
                    + " and prompt_key = ? and set_version = ?", Long.class, scopeName, prompt, version);
            for (QualityCase item : shipped.cases()) {
                jdbc.get().update("insert into ctxa_prompt_version_case_set_member (set_id, registry_scope, case_key,"
                        + " content_hash, origin, root_case_key, grade, added_at) values (?, ?, ?, ?, ?, ?, ?, ?) on"
                        + " conflict do nothing", setId, scopeName, item.key(), item.contentHash(),
                        item.origin().name(), item.rootCaseKey(), item.grade().name(), timestamp(item.addedAt()));
            }
            for (Kept kept : confirmed) {
                QualityCase item = kept.item();
                jdbc.get().update("insert into ctxa_prompt_version_case_set_member (set_id, registry_scope, case_key,"
                        + " content_hash, origin, case_id, root_case_key, grade, expectation, added_at) values"
                        + " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) on conflict do nothing", setId, scopeName, item.key(),
                        item.contentHash(), item.origin().name(), kept.id(), item.rootCaseKey(), item.grade().name(),
                        QualityCaseDocuments.writeExpectation(item.expectation()).toString(),
                        timestamp(item.addedAt()));
            }
        });
        audit.record(PromptVersionAudit.CASE_SET_PUBLISHED, scopeName, prompt, version, who,
                cases.size() + " cases, " + shipped.cases().size() + " of the default set " + shipped.version());
        return published(scopeName, prompt, version).orElseThrow();
    }

    public Optional<PublishedSet> published(long id) {
        return jdbc.get().query(SET_SQL + " where id = ?", SET_ROW, id).stream().findFirst();
    }

    public Optional<PublishedSet> published(String scope, String prompt, String version) {
        return jdbc.get().query(SET_SQL + " where registry_scope = ? and prompt_key = ? and set_version = ?", SET_ROW,
                scopeOf(scope), prompt, version).stream().findFirst();
    }

    /** The latest set published in the scope. */
    public Optional<PublishedSet> latestPublished(String scope, String prompt) {
        return jdbc.get().query(SET_SQL + " where registry_scope = ? and prompt_key = ?"
                + " order by published_at desc, id desc limit 1", SET_ROW, scopeOf(scope), prompt).stream().findFirst();
    }

    /**
     * The cases of the published set as they read now: a case of the default set from the product, a kept case with
     * its kept input and the answer it was published with. A case whose content no longer has the published hash is
     * missing, and named as such.
     */
    public ReadSet read(PublishedSet set) {
        record Member(String key, String hash, String origin, Long caseId, String grade, String expectation,
                      Instant addedAt) {
        }
        List<Member> members = jdbc.get().query("select case_key, content_hash, origin, case_id, grade, expectation,"
                + " added_at from ctxa_prompt_version_case_set_member where set_id = ? order by case_key",
                (rs, row) -> new Member(rs.getString(1), rs.getString(2), rs.getString(3),
                        (Long) rs.getObject(4), rs.getString(5), rs.getString(6), instant(rs.getTimestamp(7))),
                set.id());
        Map<Long, Kept> keptById = new LinkedHashMap<>();
        for (Kept kept : list(set.scope(), set.prompt())) {
            keptById.put(kept.id(), kept);
        }
        List<QualityCase> cases = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        for (Member member : members) {
            QualityCase item = null;
            if (QualityCaseOrigin.CONTEXA.name().equals(member.origin())) {
                item = defaultSet().find(member.key()).orElse(null);
            }
            else if (member.caseId() != null && member.expectation() != null && keptById.containsKey(member.caseId())) {
                QualityCase now = keptById.get(member.caseId()).item();
                try {
                    item = new QualityCase(now.key(), now.input(), expectation(member.expectation()),
                            QualityCaseGrade.valueOf(member.grade()), now.rootCaseKey(), now.environment(),
                            now.origin(), member.addedAt());
                }
                catch (IllegalArgumentException unreadable) {
                    item = null;
                }
            }
            if (item != null && item.contentHash().equals(member.hash())) {
                cases.add(item);
            }
            else {
                missing.add(member.key());
            }
        }
        return new ReadSet(set, new QualityCaseSet(set.name(), cases), List.copyOf(missing));
    }

    // ----- rows -----

    private static final String CASE_SQL = "select id, registry_scope, prompt_key, case_key, origin, root_case_key,"
            + " sealed_package_id, subject_user_id, grade, case_input, expectation, time_zone, context_format_version,"
            + " status, submitted_by, submitted_at, labelled_by, labelled_at, confirmed_by, confirmed_at,"
            + " second_analysis from ctxa_prompt_version_case";

    private Kept kept(ResultSet rs, int row) throws SQLException {
        Instant submittedAt = rs.getTimestamp("submitted_at").toInstant();
        QualityCase item = new QualityCase(rs.getString("case_key"),
                QualityCaseDocuments.readInput(tree(rs.getString("case_input"))),
                expectation(rs.getString("expectation")), QualityCaseGrade.valueOf(rs.getString("grade")),
                rs.getString("root_case_key"),
                new QualityCaseEnvironment(rs.getString("time_zone"), rs.getString("context_format_version")),
                QualityCaseOrigin.valueOf(rs.getString("origin")), submittedAt);
        return new Kept(rs.getLong("id"), rs.getString("registry_scope"), rs.getString("prompt_key"), item,
                rs.getString("status"), rs.getString("sealed_package_id"), rs.getString("subject_user_id"),
                rs.getString("submitted_by"), submittedAt, rs.getString("labelled_by"),
                rs.getTimestamp("labelled_at").toInstant(), rs.getString("confirmed_by"),
                instant(rs.getTimestamp("confirmed_at")), rs.getBoolean("second_analysis"));
    }

    private static final String SET_SQL = "select id, registry_scope, prompt_key, set_version, name, case_count,"
            + " default_set_version, default_case_count, published_by, published_at from ctxa_prompt_version_case_set";

    private static final RowMapper<PublishedSet> SET_ROW = (rs, row) -> new PublishedSet(rs.getLong(1),
            rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getInt(6), rs.getString(7),
            rs.getInt(8), rs.getString(9), rs.getTimestamp(10).toInstant());

    private QualityCaseExpectation expectation(String text) {
        return QualityCaseDocuments.readExpectation(tree(text));
    }

    private JsonNode tree(String text) {
        try {
            return json.readTree(text);
        }
        catch (IOException unreadable) {
            throw new IllegalStateException("A kept case is no JSON: " + unreadable.getMessage(), unreadable);
        }
    }

    static String scopeOf(String scope) {
        return scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
    }

    private static String actorOf(String actor) {
        return actor != null && !actor.isBlank() ? actor.trim() : "system";
    }

    @Nullable
    private static Timestamp timestamp(@Nullable Instant instant) {
        return instant != null ? Timestamp.from(instant) : null;
    }

    @Nullable
    private static Instant instant(@Nullable Timestamp timestamp) {
        return timestamp != null ? timestamp.toInstant() : null;
    }
}
