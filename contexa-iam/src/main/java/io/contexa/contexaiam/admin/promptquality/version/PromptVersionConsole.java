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
package io.contexa.contexaiam.admin.promptquality.version;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocument;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentException;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentWriter;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionProblem;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompts;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptReleaseQueryService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptGovernanceRuntimeCacheInvalidationService;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ActionChange;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.AdvancedView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Carried;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.CheckRow;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.CheckView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Counts;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Created;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Draft;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.DraftForm;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.DraftPart;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.FolderView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.FormPart;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.HistoryRow;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ItemView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ListView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.NewProduct;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.PartView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Preview;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ProblemView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.PromptChoice;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Receipt;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.RollbackRow;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Running;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ScanRow;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ShadowCase;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ShadowResults;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.StageOutcome;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Size;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.TrialStart;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.TrialView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Used;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.UseCheck;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.VersionRow;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.VersionView;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.VersionDecisions;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * What the prompt version screens show and do (plan 3.10), composed from the versions, the registry the labels live in,
 * the release gate every label move passes, the trials, the sealed decisions and the hourly decision table. A label is
 * moved only through the release gate, and every applied move tells the runtime caches and is audited.
 */
public class PromptVersionConsole {

    private static final Logger log = LoggerFactory.getLogger(PromptVersionConsole.class);

    /** The shares of users a canary may take (plan 3.4). */
    public static final List<Integer> CANARY_PERCENTS = List.of(10, 25, 50);
    /** The shares of requests a shadow may run on (plan 3.10, screen 5). */
    public static final List<Integer> SHADOW_PERCENTS = List.of(5, 10);
    /** The most shadow runs a day an operator may allow. */
    public static final int SHADOW_DAILY_LIMIT_MAX = 10_000;
    /** Where a label move comes from in the registry's ledger. */
    static final String SOURCE = "PROMPT_VERSION_CONSOLE";
    static final String USED = "USED";
    static final String CANARY = "CANARY";
    static final String SHADOW = "SHADOW";
    static final String UNUSED = "UNUSED";
    static final String HIDDEN = "HIDDEN";
    private static final int HISTORY_LIMIT = 50;
    private static final int SHADOW_CASE_LIMIT = 50;

    /** An operator's request the console refuses, with the code the screen names. */
    public static class RefusedException extends RuntimeException {

        private final String code;

        public RefusedException(String code) {
            super("Refused: " + code);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    private final PromptVersionService versions;
    private final Supplier<PromptVersionTrials> trials;
    private final Supplier<PromptBundleSelector> selector;
    private final Supplier<JdbcTemplate> jdbc;
    private final Supplier<JdbcPromptReleaseQueryService> releases;
    private final Supplier<PromptGovernanceReleaseGateService> gate;
    private final Supplier<PromptGovernanceRuntimeCacheInvalidationService> invalidation;
    private final Supplier<PromptBundleRollbackService> rollbacks;
    private final Supplier<JdbcPromptInspectionQueries> sealed;
    private final Supplier<ZeroTrustConsoleService> decisions;
    private final Supplier<PromptVersionFolderScanner> folder;
    private final String folderSetting;
    private final Supplier<PromptAssembler.LengthLimit> limit;
    private final PromptVersionAudit audit;
    private final Clock clock;
    private final PromptVersionDocumentReader reader = new PromptVersionDocumentReader();
    private VersionedPrompts versionedPrompts = new VersionedPrompts(List.of());
    private final PromptVersionDocumentWriter writer = new PromptVersionDocumentWriter();

    /**
     * Every collaborator but the versions may be missing in an application: a supplier gives null then, and the screen
     * shows what it can (no gate: nothing can be moved; no trials: no trial can run).
     *
     * @param folderSetting the setting {@code contexa.prompt.versions.directory}, null when not set
     */
    public PromptVersionConsole(PromptVersionService versions, Supplier<PromptVersionTrials> trials,
                                Supplier<PromptBundleSelector> selector, Supplier<JdbcTemplate> jdbc,
                                Supplier<JdbcPromptReleaseQueryService> releases,
                                Supplier<PromptGovernanceReleaseGateService> gate,
                                Supplier<PromptGovernanceRuntimeCacheInvalidationService> invalidation,
                                Supplier<PromptBundleRollbackService> rollbacks,
                                Supplier<JdbcPromptInspectionQueries> sealed,
                                Supplier<ZeroTrustConsoleService> decisions,
                                Supplier<PromptVersionFolderScanner> folder, String folderSetting,
                                Supplier<PromptAssembler.LengthLimit> limit, PromptVersionAudit audit, Clock clock) {
        this.versions = Objects.requireNonNull(versions, "versions");
        this.trials = orNone(trials);
        this.selector = orNone(selector);
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.releases = orNone(releases);
        this.gate = orNone(gate);
        this.invalidation = orNone(invalidation);
        this.rollbacks = orNone(rollbacks);
        this.sealed = orNone(sealed);
        this.decisions = orNone(decisions);
        this.folder = orNone(folder);
        this.folderSetting = folderSetting != null && !folderSetting.isBlank() ? folderSetting.trim() : null;
        this.limit = orNone(limit);
        this.audit = audit != null ? audit : PromptVersionAudit.none();
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /** Plan 3.11: the prompts other than the security decision, whose finished prompt is drawn with an example input. */
    public void setVersionedPrompts(VersionedPrompts versionedPrompts) {
        this.versionedPrompts = versionedPrompts != null ? versionedPrompts : new VersionedPrompts(List.of());
    }

    // ----- the list (screen 1) -----

    /** The prompt the screens show when the address names none: the security decision when it is shipped. */
    public String defaultPrompt() {
        List<String> prompts = versions.prompts();
        return prompts.contains(SecurityDecisionPromptDocument.PROMPT) || prompts.isEmpty()
                ? SecurityDecisionPromptDocument.PROMPT : prompts.get(0);
    }

    public ListView list(String scope, String prompt, boolean withHidden) {
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        List<PromptVersionRecord> records = versions.list(scopeName, key, true);
        Map<String, String> states = registryStates(scopeName, key);
        Used used = used(scopeName, key, records);
        List<VersionRow> rows = new ArrayList<>();
        for (PromptVersionRecord record : records) {
            if (record.hidden() && !withHidden) {
                continue;
            }
            rows.add(row(record, state(record, states, used)));
        }
        int contexa = (int) records.stream().filter(record -> !record.hidden())
                .filter(record -> PromptVersionRecord.CONTEXA.equals(record.provider())).count();
        int hidden = (int) records.stream().filter(PromptVersionRecord::hidden).count();
        return new ListView(scopeName, scopes(), key, prompts(), decisionPrompt(key), PromptVersionTrials.offeredFor(key),
                writable(), used, new Counts(records.size() - hidden, contexa, records.size() - hidden - contexa, hidden),
                running(scopeName, key), newProduct(scopeName, key, used, records), rows);
    }

    /** The prompts the build ships, the security decision first. */
    public List<PromptChoice> prompts() {
        List<String> keys = new ArrayList<>(versions.prompts());
        keys.sort(Comparator.comparing((String prompt) -> !SecurityDecisionPromptDocument.PROMPT.equals(prompt)));
        return keys.stream().map(prompt -> new PromptChoice(prompt, decisionPrompt(prompt))).toList();
    }

    /** The scopes that have versions; the screens offer a choice only when there are two or more. */
    public List<String> scopes() {
        List<String> scopes = jdbc.get().queryForList("select distinct registry_scope from ctxa_prompt_version order by"
                + " registry_scope", String.class);
        return scopes.isEmpty() ? List.of(PromptVersionService.PLATFORM_SCOPE) : scopes;
    }

    // ----- a version (screen 2) -----

    public Optional<VersionView> version(String scope, String prompt, int number) {
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        Optional<PromptVersionRecord> found = versions.find(scopeName, key, number);
        Optional<AssembledPrompt> mine = found.flatMap(record -> versions.assembled(scopeName, key, number));
        if (found.isEmpty() || mine.isEmpty()) {
            return Optional.empty();
        }
        PromptVersionRecord record = found.get();
        AssembledPrompt base = record.basedOnNumber() == null ? null
                : versions.assembled(scopeName, key, record.basedOnNumber()).orElse(null);
        List<PartView> system = compare("SYSTEM", mine.get().system(), base != null ? base.system() : null);
        List<PartView> user = compare("USER", mine.get().user(), base != null ? base.user() : null);
        Map<String, Integer> changes = new LinkedHashMap<>();
        for (String mark : List.of("CHANGED", "DELETED", "ADDED", "INCLUDED")) {
            changes.put(mark, (int) Stream.concat(system.stream(), user.stream())
                    .filter(part -> mark.equals(part.mark())).count());
        }
        Map<String, String> states = registryStates(scopeName, key);
        List<PromptVersionRecord> records = versions.list(scopeName, key, true);
        VersionDecisions made = decisionsOf(record.name(), scopeName);
        return Optional.of(new VersionView(scopeName, key, decisionPrompt(key), PromptVersionTrials.offeredFor(key),
                writable(), row(record, state(record, states, used(scopeName, key, records))), record.contentHash(),
                record.basedOnNumber() != null ? PromptVersionNames.name(record.basedOnNumber()) : null, changes, system,
                user, preview(key, mine.get(), record.name(), user),
                new Size(PromptAssembler.systemTokens(mine.get()),
                        base != null ? PromptAssembler.systemTokens(base) : null),
                made, !record.fromDocument() && !record.hidden()));
    }

    /**
     * The parts of a version against its base: kept, changed, added, a prepared part put in, or taken out; a part taken
     * out stands where it stood in the base. A product version has no base: its parts are the product default.
     */
    static List<PartView> compare(String list, List<PromptVersionDocument.Part> parts,
                                  List<PromptVersionDocument.Part> base) {
        Map<String, PromptVersionDocument.Part> before = new LinkedHashMap<>();
        if (base != null) {
            base.forEach(part -> before.put(part.key(), part));
        }
        Set<String> present = new LinkedHashSet<>();
        parts.forEach(part -> present.add(part.key()));
        // The parts the base had and this version took out, by the key of the part they followed in the base.
        Map<String, List<PromptVersionDocument.Part>> deletedAfter = new LinkedHashMap<>();
        if (base != null) {
            String previous = null;
            for (PromptVersionDocument.Part part : base) {
                if (!present.contains(part.key()) && !part.prepared()) {
                    deletedAfter.computeIfAbsent(previous, key -> new ArrayList<>()).add(part);
                }
                else if (present.contains(part.key())) {
                    previous = part.key();
                }
            }
        }
        List<PartView> views = new ArrayList<>();
        int position = 0;
        for (PromptVersionDocument.Part deleted : deletedAfter.getOrDefault(null, List.of())) {
            views.add(view(++position, list, deleted, "DELETED", deleted.text()));
        }
        for (PromptVersionDocument.Part part : parts) {
            PromptVersionDocument.Part earlier = before.get(part.key());
            if (part.prepared() && (earlier == null || earlier.prepared())) {
                // A prepared part no version put in is not drawn: the new version screen offers it.
                for (PromptVersionDocument.Part deleted : deletedAfter.getOrDefault(part.key(), List.of())) {
                    views.add(view(++position, list, deleted, "DELETED", deleted.text()));
                }
                continue;
            }
            String mark;
            String baseText = null;
            if (base == null) {
                mark = part.isLocked() ? "LOCKED" : "DEFAULT";
            }
            else if (earlier == null) {
                mark = part.action() == PromptVersionDocument.Action.INCLUDE ? "INCLUDED" : "ADDED";
            }
            else if (earlier.prepared() && !part.prepared()) {
                mark = "INCLUDED";
            }
            else if (!part.prepared() && Objects.equals(earlier.text(), part.text())
                    && Objects.equals(earlier.title(), part.title())) {
                mark = part.isLocked() ? "LOCKED" : "SAME";
            }
            else if (part.prepared()) {
                mark = "DELETED";
            }
            else {
                mark = "CHANGED";
                baseText = earlier.text();
            }
            views.add(view(++position, list, part, mark, baseText));
            for (PromptVersionDocument.Part deleted : deletedAfter.getOrDefault(part.key(), List.of())) {
                views.add(view(++position, list, deleted, "DELETED", deleted.text()));
            }
        }
        return views;
    }

    private static PartView view(int position, String list, PromptVersionDocument.Part part, String mark,
                                 String baseText) {
        return new PartView(position, list, part.key(), part.title(), part.group() != null ? part.group()
                : "SYSTEM".equals(list) ? AssembledPrompt.JUDGMENT : null, part.isLocked(), part.when(), mark,
                "DELETED".equals(mark) ? null : part.text(), baseText, items(part));
    }

    private static List<ItemView> items(PromptVersionDocument.Part part) {
        return part.items().stream().map(item -> new ItemView(item.key(), item.text(), item.use())).toList();
    }

    /**
     * The finished prompt: the system text the version draws with the host's defaults, the output format, and the user
     * prompt of the latest sealed decision of the prompt with the version it was drawn with. The user prompt's fixed
     * blocks are the same in every version; the blocks this version adds are listed beside it.
     */
    private Preview preview(String prompt, AssembledPrompt version, String name, List<PartView> user) {
        if (!decisionPrompt(prompt)) {
            // Plan 3.11: a prompt other than the security decision is shown drawn with its fixed example input.
            return versionedPrompts.find(prompt)
                    .map(found -> found.example(version))
                    .map(example -> new Preview(example.system() == null || example.system().isEmpty() ? null
                            : example.system(), null, example.user(), null, null, name, true, List.of(), true))
                    .orElseGet(() -> new Preview(null, null, null, null, null, null, false, List.of(), false));
        }
        String system = SecurityDecisionPromptDocument.systemPreview(version);
        String format = SecurityDecisionPromptDocument.outputFormatPreview();
        List<PartView> added = user.stream().filter(part -> "ADDED".equals(part.mark())).toList();
        List<Object[]> latest = jdbc.get().query("select p.raw_user_prompt, p.correlation_id, p.captured_at,"
                + " coalesce(contexa_safe_jsonb(p.prompt_execution_metadata_json) ->> '" + PromptExecutionMetadata.PROMPT_VERSION_NAME
                + "', contexa_safe_jsonb(p.prompt_execution_metadata_json) #>> '{" + PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR
                + ",promptBundleVersion}') from ctxa_sealed_evidence_package p where p.seal_state = 'SEALED' and"
                + " coalesce(contexa_safe_jsonb(p.decision_json) ->> 'decisionAppliedStage', '') <> 'SHADOW' and"
                + " p.raw_user_prompt is not null order by p.captured_at desc limit 1", (rs, row) -> new Object[] {
                rs.getString(1), rs.getString(2), rs.getTimestamp(3) != null ? rs.getTimestamp(3).toInstant() : null,
                rs.getString(4)});
        if (latest.isEmpty()) {
            return new Preview(system, format, null, null, null, null, false, added, false);
        }
        Object[] row = latest.get(0);
        String drawnWith = (String) row[3];
        return new Preview(system, format, (String) row[0], (String) row[1], (Instant) row[2], drawnWith,
                name.equals(drawnWith), added, false);
    }

    private VersionDecisions decisionsOf(String name, String scope) {
        ZeroTrustConsoleService service = decisions.get();
        if (service == null) {
            return null;
        }
        try {
            return service.versionDecisions(name, PromptVersionService.PLATFORM_SCOPE.equals(scope) ? null : scope);
        }
        catch (RuntimeException failure) {
            log.error("[PromptVersionConsole] The decisions of {} could not be read", name, failure);
            return null;
        }
    }

    // ----- a new version (screen 3) -----

    /**
     * What the new version screen starts from: the base's parts (the fixed ones folded, the others editable with the
     * product text to go back to), the prepared parts that can be put in, the places an added part may follow, and
     * with {@code carry} the changes of that version moved onto the base (a newer product version).
     */
    public Optional<Draft> draft(String scope, String prompt, int baseNumber, Integer carry) {
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        Optional<PromptVersionRecord> found = versions.find(scopeName, key, baseNumber);
        Optional<AssembledPrompt> base = found.flatMap(record -> versions.assembled(scopeName, key, baseNumber));
        if (found.isEmpty() || base.isEmpty()) {
            return Optional.empty();
        }
        AssembledPrompt product = productOf(scopeName, key, found.get());
        List<DraftPart> system = new ArrayList<>();
        List<DraftPart> prepared = new ArrayList<>();
        for (PromptVersionDocument.Part part : base.get().system()) {
            DraftPart draft = draftPart("SYSTEM", part, product != null ? product.systemPart(part.key()).orElse(null)
                    : null);
            (part.prepared() ? prepared : system).add(draft);
        }
        List<DraftPart> user = base.get().user().stream()
                .map(part -> draftPart("USER", part, product != null ? product.userBlock(part.key()).orElse(null) : null))
                .toList();
        List<String> systemPlaces = base.get().system().stream().filter(part -> !part.prepared())
                .filter(part -> AssembledPrompt.JUDGMENT.equals(part.group() != null ? part.group() : AssembledPrompt.JUDGMENT))
                .map(PromptVersionDocument.Part::key).toList();
        List<String> userPlaces = base.get().user().stream().map(PromptVersionDocument.Part::key).toList();
        List<Carried> carried = List.of();
        String carriedFrom = null;
        if (carry != null) {
            Optional<PromptVersionRecord> carrying = versions.find(scopeName, key, carry);
            if (carrying.isPresent()) {
                carried = carried(reader.read(carrying.get().document()), base.get());
                carriedFrom = carrying.get().name();
            }
        }
        int next = versions.list(scopeName, key, true).stream().mapToInt(PromptVersionRecord::number).max().orElse(0) + 1;
        return Optional.of(new Draft(scopeName, key, decisionPrompt(key), baseNumber, found.get().name(),
                found.get().title(), found.get().contentHash(), found.get().fromDocument(), PromptVersionNames.name(next),
                system, user, prepared, systemPlaces, userPlaces, carried, carriedFrom,
                PromptAssembler.systemTokens(base.get())));
    }

    private static DraftPart draftPart(String list, PromptVersionDocument.Part part,
                                       PromptVersionDocument.Part productPart) {
        boolean editable = !part.isLocked() && !part.prepared() && part.items().isEmpty();
        return new DraftPart(list, part.key(), part.title(), part.group() != null ? part.group()
                : "SYSTEM".equals(list) ? AssembledPrompt.JUDGMENT : null, part.isLocked(), part.prepared(), part.when(),
                part.text(), productPart != null ? productPart.text() : null, items(part), editable,
                part.action() == PromptVersionDocument.Action.INCLUDE);
    }

    /** The changes of an organization's document, each with whether the base can take it. */
    static List<Carried> carried(PromptVersionDocument changes, AssembledPrompt base) {
        List<Carried> carried = new ArrayList<>();
        Set<String> added = new LinkedHashSet<>();
        for (PromptVersionDocument.Part part : changes.system()) {
            carried.add(carriedPart("SYSTEM", part, base.systemPart(part.key()).orElse(null),
                    part.addAfter() != null && (base.systemPart(part.addAfter()).isPresent()
                            || added.contains(part.addAfter()))));
            if (part.action() == PromptVersionDocument.Action.ADD) {
                added.add(part.key());
            }
        }
        added.clear();
        for (PromptVersionDocument.Part part : changes.user()) {
            carried.add(carriedPart("USER", part, base.userBlock(part.key()).orElse(null),
                    part.addAfter() != null && (base.userBlock(part.addAfter()).isPresent()
                            || added.contains(part.addAfter()))));
            if (part.action() == PromptVersionDocument.Action.ADD) {
                added.add(part.key());
            }
        }
        return carried;
    }

    private static Carried carriedPart(String list, PromptVersionDocument.Part part, PromptVersionDocument.Part inBase,
                                       boolean placeFound) {
        boolean movable = switch (part.action()) {
            case ADD -> inBase == null && placeFound;
            case INCLUDE -> inBase != null && inBase.prepared();
            case CHANGE, DELETE -> inBase != null && !inBase.isLocked() && !inBase.prepared();
            case BASE -> false;
        };
        return new Carried(list, part.key(), part.action().name(), part.title(), part.text(), part.addAfter(), movable);
    }

    /** The product version a version stands on, followed down its chain of bases. */
    private AssembledPrompt productOf(String scope, String prompt, PromptVersionRecord record) {
        PromptVersionRecord current = record;
        for (int depth = 0; current != null && current.basedOnNumber() != null && depth < 1_000; depth++) {
            current = versions.find(scope, prompt, current.basedOnNumber()).orElse(null);
        }
        return current == null ? null : versions.assembled(scope, prompt, current.number()).orElse(null);
    }

    /** The checks before saving (plan 3.5) of what the new version screen holds. */
    public CheckView check(String scope, DraftForm form) {
        String scopeName = scopeOf(scope);
        String yaml = documentOf(scopeName, form);
        // The length limit is the decision prompt's (plan 3.5, check 4); another prompt shows none (plan 3.11).
        PromptAssembler.LengthLimit lengthLimit = decisionPrompt(promptOf(form.prompt())) ? limit.get() : null;
        PromptVersionService.Preview preview;
        try {
            preview = versions.check(scopeName, yaml, PromptVersionRecord.SCREEN, lengthLimit);
        }
        catch (PromptVersionDocumentException refused) {
            return checkView(refused.problems(), 0, 0, lengthLimit);
        }
        return checkView(preview.problems(), preview.baseSystemTokens(), preview.systemTokens(), lengthLimit);
    }

    private CheckView checkView(List<PromptVersionProblem> problems, int baseTokens, int tokens,
                                PromptAssembler.LengthLimit lengthLimit) {
        Set<PromptVersionProblem.Code> codes = problems.stream().map(PromptVersionProblem::code)
                .collect(Collectors.toSet());
        List<CheckRow> checks = List.of(
                new CheckRow("LOCKED", !codes.contains(PromptVersionProblem.Code.LOCKED_PART)),
                new CheckRow("PLACES", !(codes.contains(PromptVersionProblem.Code.UNKNOWN_PART)
                        || codes.contains(PromptVersionProblem.Code.UNKNOWN_PLACE)
                        || codes.contains(PromptVersionProblem.Code.NOT_PREPARED))),
                new CheckRow("CONTENT", !(codes.contains(PromptVersionProblem.Code.EMPTY_TITLE)
                        || codes.contains(PromptVersionProblem.Code.EMPTY_TEXT)
                        || codes.contains(PromptVersionProblem.Code.DUPLICATE_KEY))),
                new CheckRow("LENGTH", !codes.contains(PromptVersionProblem.Code.TOO_LONG)));
        Long delta = null;
        Double msPerToken = msPerInputToken();
        if (msPerToken != null && (tokens != 0 || baseTokens != 0)) {
            delta = Math.round((tokens - baseTokens) * msPerToken);
        }
        return new CheckView(problems.isEmpty(), checks, problems.stream()
                .map(problem -> new ProblemView(problem.code().name(), problem.where(), problem.detail())).toList(),
                baseTokens, tokens, delta, lengthLimit != null ? lengthLimit.contextTokens() : null);
    }

    /** The median decision time per input token of the latest decisions; null without any. */
    private Double msPerInputToken() {
        try {
            return jdbc.get().query("select percentile_cont(0.5) within group (order by latency::float / tokens) from"
                    + " (select llm_latency_ms as latency, prompt_tokens as tokens from ctxa_ai_security_decision_observation"
                    + " where llm_latency_ms > 0 and prompt_tokens > 0 order by created_at desc limit 200) recent",
                    (rs, row) -> (Double) rs.getObject(1)).stream().filter(Objects::nonNull).findFirst().orElse(null);
        }
        catch (RuntimeException unreadable) {
            log.error("[PromptVersionConsole] The decision time per token could not be read", unreadable);
            return null;
        }
    }

    /** Saves what the screen holds as the next version, and uses it for decisions when the screen asked to. */
    public Created create(String scope, DraftForm form, String actor) {
        String scopeName = scopeOf(scope);
        String key = promptOf(form.prompt());
        PromptVersionService.Saved saved = versions.create(scopeName, documentOf(scopeName, form),
                PromptVersionRecord.SCREEN, null, actor, limit.get());
        Receipt used = Boolean.TRUE.equals(form.useNow())
                ? use(scopeName, key, saved.number(), actor, form.reason()) : null;
        return new Created(saved.number(), saved.name(), saved.contentHash(), saved.made(), used);
    }

    /** The organization's document of the form: its base by number and content hash, and only what it changes. */
    String documentOf(String scope, DraftForm form) {
        if (form == null || form.base() == null) {
            throw new RefusedException("BASE_REQUIRED");
        }
        String key = promptOf(form.prompt());
        PromptVersionRecord base = versions.find(scope, key, form.base())
                .orElseThrow(() -> new RefusedException("BASE_NOT_FOUND"));
        return writer.write(new PromptVersionDocument(key, PromptVersionDocument.Kind.ORGANIZATION, null, base.name(),
                "sha256:" + base.contentHash(), blankAsNull(form.title()), blankAsNull(form.description()),
                parts(form.system()), parts(form.user()), List.of()));
    }

    private static List<PromptVersionDocument.Part> parts(List<FormPart> form) {
        if (form == null) {
            return List.of();
        }
        List<PromptVersionDocument.Part> parts = new ArrayList<>();
        for (FormPart part : form) {
            if (part == null || part.key() == null || part.key().isBlank()) {
                continue;
            }
            PromptVersionDocument.Action action;
            try {
                action = PromptVersionDocument.Action.valueOf(String.valueOf(part.action()).trim());
            }
            catch (IllegalArgumentException unknown) {
                throw new RefusedException("ACTION");
            }
            if (action == PromptVersionDocument.Action.BASE) {
                throw new RefusedException("ACTION");
            }
            boolean bare = action == PromptVersionDocument.Action.DELETE || action == PromptVersionDocument.Action.INCLUDE;
            parts.add(new PromptVersionDocument.Part(part.key().trim(), bare ? null : blankAsNull(part.title()), null,
                    null, action == PromptVersionDocument.Action.ADD, null, null, false,
                    bare ? null : part.text(), null, null, null, action,
                    action == PromptVersionDocument.Action.ADD ? blankAsNull(part.addAfter()) : null));
        }
        return parts;
    }

    // ----- labels -----

    /** What the confirmation of "use for decisions" shows (plan 3.4, 3.9): the gate's answer and the latest trial. */
    public UseCheck useCheck(String scope, String prompt, int number) {
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        String name = PromptVersionNames.name(number);
        Used used = used(scopeName, key, versions.list(scopeName, key, true));
        boolean ready = false;
        List<String> blockers = List.of();
        PromptGovernanceReleaseGateService releaseGate = gate.get();
        if (releaseGate != null) {
            try {
                Optional<PromptGovernanceReleaseGateService.ReleaseGateTarget> active = releaseGate
                        .assessPromptRelease(scopeName, key, name).targets().stream()
                        .filter(target -> PromptBundleState.is(target.targetState(), PromptBundleState.ACTIVE))
                        .findFirst();
                ready = active.map(PromptGovernanceReleaseGateService.ReleaseGateTarget::ready).orElse(false);
                blockers = active.map(PromptGovernanceReleaseGateService.ReleaseGateTarget::blockers).orElse(List.of());
            }
            catch (RuntimeException failure) {
                log.error("[PromptVersionConsole] The release gate could not assess {} {}", key, name, failure);
                blockers = List.of("GATE_UNREADABLE");
            }
        }
        else {
            blockers = List.of("GATE_MISSING");
        }
        PromptVersionTrials trial = trials.get();
        return new UseCheck(name, used != null ? used.version() : null, ready, blockers,
                trial != null ? trial.latestDone(scopeName, key, number).orElse(null) : null);
    }

    /** Uses the version for decisions (plan 3.4): the label moves through the release gate; a rollback is the same. */
    public Receipt use(String scope, String prompt, int number, String actor, String reason) {
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        PromptVersionRecord record = shown(scopeName, key, number);
        String previous = Optional.ofNullable(used(scopeName, key, versions.list(scopeName, key, true)))
                .map(Used::version).orElse(null);
        Receipt receipt = move(scopeName, key, record.name(), PromptBundleState.ACTIVE, actor, reason, previous);
        if (receipt.applied()) {
            audit.record(PromptVersionAudit.USED_FOR_DECISIONS, scopeName, key, record.name(), actor,
                    previous != null ? previous + " -> " + record.name() + blankOrReason(reason) : blankAsNull(reason));
        }
        return receipt;
    }

    /** Hides a version (plan 3.3); one in use, a canary or a shadow cannot be hidden. */
    public void hide(String scope, String prompt, int number, String actor) {
        versions.hide(scopeOf(scope), promptOf(prompt), number, actor);
    }

    /** Starts a canary of the version (plan 3.4): a share of users, and the tenants and addresses it covers. */
    public Receipt startCanary(String scope, String prompt, int number, int percent, String tenants, String paths,
                               String actor, String reason) {
        if (!CANARY_PERCENTS.contains(percent)) {
            throw new RefusedException("CANARY_PERCENT");
        }
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        PromptVersionRecord record = shown(scopeName, key, number);
        if (labelled(scopeName, key, PromptBundleState.CANARY).filter(version -> !version.equals(record.name()))
                .isPresent()) {
            throw new RefusedException("CANARY_RUNNING");
        }
        jdbc.get().update("update ctxa_prompt_governance_registry set canary_percent = ?, canary_tenants = ?,"
                + " canary_resource_families = ?, updated_at = ? where registry_scope = ? and prompt_key = ? and"
                + " prompt_version = ?", percent, list(tenants), list(paths), Timestamp.from(clock.instant()), scopeName,
                key, record.name());
        Receipt receipt = move(scopeName, key, record.name(), PromptBundleState.CANARY, actor, reason, null);
        if (receipt.applied()) {
            audit.record(PromptVersionAudit.CANARY_STARTED, scopeName, key, record.name(), actor,
                    percent + "%" + blankOrReason(reason));
        }
        return receipt;
    }

    public Receipt stopCanary(String scope, String prompt, String actor, String reason) {
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        String version = labelled(scopeName, key, PromptBundleState.CANARY)
                .orElseThrow(() -> new RefusedException("NO_CANARY"));
        Receipt receipt = move(scopeName, key, version, PromptBundleState.AVAILABLE, actor, reason, null);
        if (receipt.applied()) {
            jdbc.get().update("update ctxa_prompt_governance_registry set canary_percent = null, canary_tenants = null,"
                    + " canary_resource_families = null where registry_scope = ? and prompt_key = ? and prompt_version = ?",
                    scopeName, key, version);
            audit.record(PromptVersionAudit.CANARY_STOPPED, scopeName, key, version, actor, blankAsNull(reason));
        }
        return receipt;
    }

    /** Runs the version alongside the decisions (plan 3.4): a share of requests, within a number of runs a day. */
    public Receipt startShadow(String scope, String prompt, int number, int samplePercent, int dailyLimit,
                               String actor, String reason) {
        if (!SHADOW_PERCENTS.contains(samplePercent)) {
            throw new RefusedException("SHADOW_PERCENT");
        }
        if (dailyLimit < 1 || dailyLimit > SHADOW_DAILY_LIMIT_MAX) {
            throw new RefusedException("SHADOW_DAILY_LIMIT");
        }
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        PromptVersionRecord record = shown(scopeName, key, number);
        if (labelled(scopeName, key, PromptBundleState.SHADOW).filter(version -> !version.equals(record.name()))
                .isPresent()) {
            throw new RefusedException("SHADOW_RUNNING");
        }
        jdbc.get().update("update ctxa_prompt_governance_registry set shadow_sample_percent = ?, shadow_daily_limit = ?,"
                + " updated_at = ? where registry_scope = ? and prompt_key = ? and prompt_version = ?", samplePercent,
                dailyLimit, Timestamp.from(clock.instant()), scopeName, key, record.name());
        Receipt receipt = move(scopeName, key, record.name(), PromptBundleState.SHADOW, actor, reason, null);
        if (receipt.applied()) {
            audit.record(PromptVersionAudit.SHADOW_STARTED, scopeName, key, record.name(), actor,
                    samplePercent + "% " + dailyLimit + "/day" + blankOrReason(reason));
        }
        return receipt;
    }

    public Receipt stopShadow(String scope, String prompt, String actor, String reason) {
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        String version = labelled(scopeName, key, PromptBundleState.SHADOW)
                .orElseThrow(() -> new RefusedException("NO_SHADOW"));
        Receipt receipt = move(scopeName, key, version, PromptBundleState.AVAILABLE, actor, reason, null);
        if (receipt.applied()) {
            jdbc.get().update("update ctxa_prompt_governance_registry set shadow_sample_percent = null,"
                    + " shadow_daily_limit = null where registry_scope = ? and prompt_key = ? and prompt_version = ?",
                    scopeName, key, version);
            audit.record(PromptVersionAudit.SHADOW_STOPPED, scopeName, key, version, actor, blankAsNull(reason));
        }
        return receipt;
    }

    /** Rolls back at once to an earlier version (plan 3.4): applied now, finished when another operator approves. */
    public PromptBundleRollbackService.Result emergencyRollback(String scope, String prompt, int number, String reason,
                                                                String actor) {
        PromptBundleRollbackService service = rollbacks.get();
        if (service == null) {
            throw new RefusedException("ROLLBACK_MISSING");
        }
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        PromptVersionRecord record = shown(scopeName, key, number);
        String current = Optional.ofNullable(used(scopeName, key, versions.list(scopeName, key, true)))
                .map(Used::version).orElse(null);
        PromptBundleRollbackService.Result result = service.rollback(new PromptBundleRollbackService.Request(scopeName,
                key, current, record.name(), reason, true), actor);
        if (!PromptBundleRollbackService.REFUSED.equals(result.status())
                && !PromptBundleRollbackService.INCOMPLETE.equals(result.status())) {
            tell(scopeName, key, record.name(), "emergency rollback", actor);
            audit.record(PromptVersionAudit.EMERGENCY_ROLLBACK, scopeName, key, record.name(), actor,
                    current + " -> " + record.name() + blankOrReason(reason));
        }
        return result;
    }

    public PromptBundleRollbackService.Result approveRollback(String scope, String prompt, String executionKey,
                                                              String actor) {
        PromptBundleRollbackService service = rollbacks.get();
        if (service == null) {
            throw new RefusedException("ROLLBACK_MISSING");
        }
        PromptBundleRollbackService.Result result = service.approve(executionKey, actor);
        if (!PromptBundleRollbackService.REFUSED.equals(result.status())) {
            audit.record(PromptVersionAudit.ROLLBACK_APPROVED, scopeOf(scope), promptOf(prompt), executionKey, actor, null);
        }
        return result;
    }

    private Receipt move(String scope, String prompt, String version, PromptBundleState target, String actor,
                         String reason, String previous) {
        PromptGovernanceReleaseGateService releaseGate = gate.get();
        if (releaseGate == null) {
            return new Receipt(false, version, previous, null, List.of("GATE_MISSING"));
        }
        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = releaseGate.transitionPromptRelease(scope,
                prompt, version, target, actor, blankAsNull(reason) != null ? reason.trim() : target.name(), SOURCE);
        if (receipt.applied()) {
            tell(scope, prompt, version, "prompt version " + target.name(), actor);
        }
        return new Receipt(receipt.applied(), version, previous,
                receipt.gateState(), receipt.blockers() != null ? receipt.blockers() : List.of());
    }

    private void tell(String scope, String prompt, String version, String why, String actor) {
        PromptGovernanceRuntimeCacheInvalidationService caches = invalidation.get();
        if (caches != null) {
            caches.publish(scope, prompt, version, why, actor);
        }
    }

    // ----- the trials (screen 4) -----

    public TrialStart trials(String scope, String prompt) {
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        List<PromptVersionRecord> records = versions.list(scopeName, key, false);
        Map<String, String> states = registryStates(scopeName, key);
        Used used = used(scopeName, key, versions.list(scopeName, key, true));
        PromptVersionTrials trial = trials.get();
        return new TrialStart(scopeName, key, trial != null && PromptVersionTrials.offeredFor(key),
                records.stream().map(record -> row(record, state(record, states, used))).toList(),
                used != null ? used.version() : null, PromptVersionTrials.COUNTS,
                trial != null ? trial.recent(scopeName, key, 10) : List.of());
    }

    public Optional<TrialView> trial(long id) {
        PromptVersionTrials trial = trials.get();
        if (trial == null) {
            return Optional.empty();
        }
        return trial.result(id).map(result -> new TrialView(result.trial().scope(), result.trial().prompt(), result,
                writable()));
    }

    public long startTrial(String scope, String prompt, int candidate, int reference, int count, String actor) {
        PromptVersionTrials trial = trials.get();
        if (trial == null) {
            throw new RefusedException("TRIALS_MISSING");
        }
        return trial.start(scopeOf(scope), promptOf(prompt), candidate, reference, count, actor);
    }

    public boolean cancelTrial(long id, String actor) {
        PromptVersionTrials trial = trials.get();
        return trial != null && trial.cancel(id, actor);
    }

    /**
     * The shadow runs of the period paired with the decisions of their requests (plan 3.9, "results alongside"), of
     * every version of the prompt, so a shadow that stopped keeps its results for the period, as the release
     * comparison showed them.
     */
    public ShadowResults shadowResults(String scope, String prompt, Instant from, Instant to) {
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        String shadow = labelled(scopeName, key, PromptBundleState.SHADOW).orElse(null);
        JdbcPromptInspectionQueries queries = sealed.get();
        List<String> names = versions.list(scopeName, key, true).stream().map(PromptVersionRecord::name).toList();
        List<JdbcPromptInspectionQueries.ShadowPair> pairs = queries == null || names.isEmpty() ? List.of()
                : queries.shadowPairs(from, to, names);
        // Plan 3.9: the sealed decisions of the period per version, stage and action, as the release comparison showed.
        List<StageOutcome> outcomes = queries == null || names.isEmpty() ? List.of()
                : queries.bundleOutcomes(from, to, names).stream().map(outcome -> new StageOutcome(
                        outcome.bundleVersion(), outcome.stage(), outcome.action(), outcome.packages(), outcome.failed(),
                        outcome.passed(), outcome.notInspected())).toList();
        return shadowResults(shadow, from, to, pairs, outcomes);
    }

    /** The pairs counted: how many found their decision, how many answered otherwise, those first. */
    static ShadowResults shadowResults(String shadow, Instant from, Instant to,
                                       List<JdbcPromptInspectionQueries.ShadowPair> shadows,
                                       List<StageOutcome> outcomes) {
        List<JdbcPromptInspectionQueries.ShadowPair> paired = shadows.stream()
                .filter(pair -> pair.decisionPackageId() != null).toList();
        Map<List<String>, Long> byActions = paired.stream().collect(Collectors.groupingBy(
                pair -> Arrays.asList(pair.decisionAction(), pair.shadowAction()), LinkedHashMap::new,
                Collectors.counting()));
        List<ActionChange> changes = byActions.entrySet().stream()
                .map(entry -> new ActionChange(entry.getKey().get(0), entry.getKey().get(1), entry.getValue()))
                .sorted(Comparator.comparing(ActionChange::requests).reversed()).toList();
        long otherwise = paired.stream().filter(pair -> !Objects.equals(pair.decisionAction(), pair.shadowAction()))
                .count();
        List<ShadowCase> cases = paired.stream()
                .sorted(Comparator.comparing((JdbcPromptInspectionQueries.ShadowPair pair) ->
                        Objects.equals(pair.decisionAction(), pair.shadowAction())))
                .limit(SHADOW_CASE_LIMIT)
                .map(pair -> new ShadowCase(pair.requestId(), pair.capturedAt(), pair.shadowBundleVersion(),
                        pair.shadowAction(), pair.decisionBundleVersion(), pair.decisionAction(), pair.shadowPackageId(),
                        pair.decisionPackageId()))
                .toList();
        return new ShadowResults(shadow, from, to, shadows.size(), paired.size(), otherwise, changes, cases,
                List.copyOf(outcomes));
    }

    // ----- advanced (screen 5) -----

    public AdvancedView advanced(String scope, String prompt) {
        String scopeName = scopeOf(scope);
        String key = promptOf(prompt);
        List<PromptVersionRecord> records = versions.list(scopeName, key, true);
        Map<String, String> states = registryStates(scopeName, key);
        Used used = used(scopeName, key, records);
        List<VersionRow> rows = records.stream().filter(record -> !record.hidden())
                .map(record -> row(record, state(record, states, used))).toList();
        return new AdvancedView(scopeName, key, decisionPrompt(key), writable(), folder(scopeName, key),
                running(scopeName, key), used != null ? used.version() : null, rows, history(scopeName, key),
                rollbacks(scopeName, key), CANARY_PERCENTS, SHADOW_PERCENTS);
    }

    public FolderView folder(String scope, String prompt) {
        List<ScanRow> scans = jdbc.get().query("select node_name, folder, scanned_at, document_count, registered_count,"
                + " errors from ctxa_prompt_version_folder_scan order by scanned_at desc, id desc limit 10",
                (rs, row) -> new ScanRow(rs.getString(1), rs.getString(2),
                        rs.getTimestamp(3) != null ? rs.getTimestamp(3).toInstant() : null, rs.getInt(4), rs.getInt(5),
                        errors(rs.getString(6))));
        Map<String, ScanRow> latestPerNode = new LinkedHashMap<>();
        scans.forEach(scan -> latestPerNode.putIfAbsent(scan.node(), scan));
        Optional<PromptVersionRecord> last = versions.list(scope, prompt, true).stream()
                .filter(record -> PromptVersionRecord.FOLDER.equals(record.origin())).findFirst();
        Map<String, String> states = registryStates(scope, prompt);
        return new FolderView(folderSetting, folder.get() != null, List.copyOf(latestPerNode.values()),
                last.map(record -> row(record, state(record, states, null))).orElse(null));
    }

    /** Reads the document folder now; refused when no folder is set. */
    public PromptVersionFolderScanner.Scan rescan() {
        PromptVersionFolderScanner scanner = folder.get();
        if (scanner == null) {
            throw new RefusedException("FOLDER_NOT_SET");
        }
        return scanner.scan();
    }

    public Optional<String> export(String scope, String prompt, int number, boolean full) {
        return versions.export(scopeOf(scope), promptOf(prompt), number, full);
    }

    public Created importDocument(String scope, String fileName, String text, String actor) {
        if (text == null || text.isBlank()) {
            throw new RefusedException("EMPTY_DOCUMENT");
        }
        PromptVersionService.Saved saved = versions.importDocument(scopeOf(scope), text, blankAsNull(fileName), actor,
                limit.get());
        return new Created(saved.number(), saved.name(), saved.contentHash(), saved.made(), null);
    }

    /** What was done to the versions of the prompt, from the audit log, newest first. */
    public List<HistoryRow> history(String scope, String prompt) {
        try {
            return jdbc.get().query("select timestamp, principal_name, action, resource_identifier, reason from"
                    + " ctxa_audit_log where action like 'PROMPT_VERSION_%' and resource_identifier like ? and"
                    + " coalesce(contexa_safe_jsonb(details) ->> 'scope', ?) = ? order by timestamp desc limit ?",
                    (rs, row) -> new HistoryRow(rs.getTimestamp(1) != null ? rs.getTimestamp(1).toInstant() : null,
                            rs.getString(2), rs.getString(3), versionOf(rs.getString(4)), rs.getString(5)),
                    prompt + "@%", scope, scope, HISTORY_LIMIT);
        }
        catch (RuntimeException unreadable) {
            log.error("[PromptVersionConsole] The history of {} could not be read", prompt, unreadable);
            return List.of();
        }
    }

    private List<RollbackRow> rollbacks(String scope, String prompt) {
        return jdbc.get().query("select execution_key, from_version, to_version, actor, reason, emergency, status,"
                + " executed_at, approved_by, approved_at from ctxa_prompt_governance_rollback_execution where"
                + " registry_scope = ? and prompt_key = ? order by executed_at desc limit 20", (rs, row) ->
                new RollbackRow(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5),
                        rs.getBoolean(6), rs.getString(7),
                        rs.getTimestamp(8) != null ? rs.getTimestamp(8).toLocalDateTime() : null, rs.getString(9),
                        rs.getTimestamp(10) != null ? rs.getTimestamp(10).toLocalDateTime() : null), scope, prompt);
    }

    // ----- the parts every screen reads -----

    /**
     * The version decisions run now, by the resolver's order (plan 3.4): the label, else the setting, else the newest
     * Contexa version; null when no version of the prompt is registered.
     */
    Used used(String scope, String prompt, List<PromptVersionRecord> records) {
        PromptBundleSelection selection = null;
        PromptBundleSelector resolve = selector.get();
        if (resolve != null && decisionPrompt(prompt)) {
            try {
                selection = resolve.select(new PromptGovernanceResolutionContext(scope, prompt, null,
                        PromptVersionService.PLATFORM_SCOPE.equals(scope) ? null : scope, null, null, null, Map.of()),
                        null);
            }
            catch (RuntimeException failure) {
                log.error("[PromptVersionConsole] The version in use of {} could not be resolved", prompt, failure);
            }
        }
        String name = selection != null ? selection.bundleVersion() : null;
        String source = selection != null && name != null ? selection.source().name() : null;
        if (name == null) {
            name = labelled(scope, prompt, PromptBundleState.ACTIVE).orElse(null);
            source = name != null ? "REGISTRY" : null;
        }
        if (name == null) {
            Optional<PromptVersionRecord> latest = records.stream().filter(record -> !record.hidden())
                    .filter(record -> PromptVersionRecord.CONTEXA.equals(record.provider())).findFirst();
            name = latest.map(PromptVersionRecord::name).orElse(null);
            source = name != null ? "BUILD_DEFAULT" : "NONE";
        }
        String version = name;
        Optional<PromptVersionRecord> record = records.stream().filter(one -> one.name().equals(version)).findFirst();
        if (record.isEmpty()) {
            return new Used(null, null, "NONE", null, null, 0, null);
        }
        Instant since = "REGISTRY".equals(source) ? labelledSince(scope, prompt, version) : null;
        return new Used(version, record.get().title(), source, since,
                record.get().basedOnNumber() != null ? PromptVersionNames.name(record.get().basedOnNumber()) : null,
                changes(record.get()), record.get().createdBy());
    }

    private Running running(String scope, String prompt) {
        JdbcPromptReleaseQueryService query = releases.get();
        String canary = null;
        Integer canaryPercent = null;
        String canaryTenants = null;
        String canaryPaths = null;
        if (query != null) {
            for (JdbcPromptReleaseQueryService.PromptReleaseRow row : query.releases(scope).releases()) {
                if (prompt.equals(row.promptKey()) && PromptBundleState.is(row.releaseStatus(), PromptBundleState.CANARY)) {
                    canary = row.promptVersion();
                    canaryPercent = row.canaryPercent();
                    canaryTenants = row.canaryTenants();
                    canaryPaths = row.canaryResourceFamilies();
                }
            }
        }
        String shadow = labelled(scope, prompt, PromptBundleState.SHADOW).orElse(null);
        Integer[] shadowSettings = shadow == null ? new Integer[2] : shadowSettings(scope, prompt, shadow);
        PromptVersionTrials trial = trials.get();
        PromptVersionTrials.Trial open = trial == null ? null : trial.recent(scope, prompt, 1).stream()
                .filter(one -> PromptVersionTrials.QUEUED.equals(one.status())
                        || PromptVersionTrials.RUNNING.equals(one.status())).findFirst().orElse(null);
        return new Running(canary, canaryPercent, canaryTenants, canaryPaths, shadow, shadowSettings[0],
                shadowSettings[1], open);
    }

    private Integer[] shadowSettings(String scope, String prompt, String version) {
        try {
            return jdbc.get().query("select shadow_sample_percent, shadow_daily_limit from"
                    + " ctxa_prompt_governance_registry where registry_scope = ? and prompt_key = ? and prompt_version = ?",
                    (rs, row) -> new Integer[] {(Integer) rs.getObject(1), (Integer) rs.getObject(2)}, scope, prompt,
                    version).stream().findFirst().orElse(new Integer[2]);
        }
        catch (RuntimeException unreadable) {
            log.error("[PromptVersionConsole] The shadow settings of {} {} could not be read", prompt, version,
                    unreadable);
            return new Integer[2];
        }
    }

    /** A product version newer than the product version the version in use stands on (plan 3.3). */
    private NewProduct newProduct(String scope, String prompt, Used used, List<PromptVersionRecord> records) {
        if (used == null || used.version() == null) {
            return null;
        }
        Optional<PromptVersionRecord> current = records.stream().filter(record -> record.name().equals(used.version()))
                .findFirst();
        Optional<PromptVersionRecord> newest = records.stream().filter(record -> !record.hidden())
                .filter(record -> PromptVersionRecord.CONTEXA.equals(record.provider())).findFirst();
        if (current.isEmpty() || newest.isEmpty()) {
            return null;
        }
        if (PromptVersionRecord.CONTEXA.equals(current.get().provider())) {
            // An older Contexa version in use: the label stayed where it was when the newer one was registered.
            return newest.get().number() > current.get().number() ? new NewProduct(newest.get().name(),
                    newest.get().number(), used.version(), current.get().name(), false) : null;
        }
        if (!PromptVersionRecord.ORGANIZATION.equals(current.get().provider())) {
            return null;
        }
        PromptVersionRecord base = current.get();
        for (int depth = 0; base.basedOnNumber() != null && depth < 1_000; depth++) {
            Integer number = base.basedOnNumber();
            PromptVersionRecord next = records.stream().filter(record -> record.number() == number).findFirst()
                    .orElse(null);
            if (next == null) {
                break;
            }
            base = next;
        }
        return newest.get().number() > base.number() ? new NewProduct(newest.get().name(), newest.get().number(),
                used.version(), base.name(), true) : null;
    }

    private Map<String, String> registryStates(String scope, String prompt) {
        Map<String, String> states = new LinkedHashMap<>();
        JdbcPromptReleaseQueryService query = releases.get();
        if (query == null) {
            return states;
        }
        try {
            for (JdbcPromptReleaseQueryService.PromptReleaseRow row : query.releases(scope).releases()) {
                if (prompt.equals(row.promptKey())) {
                    states.put(row.promptVersion(), row.releaseStatus());
                }
            }
        }
        catch (RuntimeException unreadable) {
            log.error("[PromptVersionConsole] The registry of {} could not be read", prompt, unreadable);
        }
        return states;
    }

    private Optional<String> labelled(String scope, String prompt, PromptBundleState state) {
        return registryStates(scope, prompt).entrySet().stream()
                .filter(entry -> PromptBundleState.is(entry.getValue(), state))
                .filter(entry -> PromptVersionNames.number(entry.getKey()).isPresent())
                .map(Map.Entry::getKey).findFirst();
    }

    private Instant labelledSince(String scope, String prompt, String version) {
        JdbcPromptReleaseQueryService query = releases.get();
        if (query == null) {
            return null;
        }
        return query.releases(scope).releases().stream()
                .filter(row -> prompt.equals(row.promptKey()) && version.equals(row.promptVersion()))
                .map(JdbcPromptReleaseQueryService.PromptReleaseRow::updatedAt).filter(Objects::nonNull)
                // The column has no time zone: the row was written in the server's zone, so it is read in it.
                .map(time -> time.atZone(ZoneId.systemDefault()).toInstant()).findFirst().orElse(null);
    }

    private static String state(PromptVersionRecord record, Map<String, String> states, Used used) {
        if (record.hidden()) {
            return HIDDEN;
        }
        String stored = states.get(record.name());
        if (PromptBundleState.is(stored, PromptBundleState.ACTIVE)
                || used != null && record.name().equals(used.version())) {
            return USED;
        }
        if (PromptBundleState.is(stored, PromptBundleState.CANARY)) {
            return CANARY;
        }
        if (PromptBundleState.is(stored, PromptBundleState.SHADOW)) {
            return SHADOW;
        }
        return UNUSED;
    }

    private VersionRow row(PromptVersionRecord record, String state) {
        return new VersionRow(record.number(), record.name(), record.title(), record.description(), record.provider(),
                record.origin(), PromptVersionRecord.SCREEN.equals(record.origin()) ? null : record.originName(),
                record.basedOnNumber() != null ? PromptVersionNames.name(record.basedOnNumber()) : null,
                record.createdAt(), record.createdBy(), record.hidden(), state, record.fromDocument(), changes(record));
    }

    /** How many parts an organization's document changes, deletes, adds or puts in; 0 for a product version. */
    private int changes(PromptVersionRecord record) {
        if (record.basedOnNumber() == null) {
            return 0;
        }
        try {
            PromptVersionDocument document = reader.read(record.document());
            return document.system().size() + document.user().size();
        }
        catch (RuntimeException unreadable) {
            log.error("[PromptVersionConsole] The document of {} {} could not be read", record.prompt(), record.name(),
                    unreadable);
            return 0;
        }
    }

    private PromptVersionRecord shown(String scope, String prompt, int number) {
        PromptVersionRecord record = versions.find(scope, prompt, number)
                .orElseThrow(() -> new RefusedException("VERSION_NOT_FOUND"));
        if (record.hidden()) {
            throw new RefusedException("VERSION_HIDDEN");
        }
        return record;
    }

    private boolean writable() {
        return gate.get() != null;
    }

    static boolean decisionPrompt(String prompt) {
        return SecurityDecisionPromptDocument.PROMPT.equals(prompt);
    }

    private String promptOf(String prompt) {
        if (prompt == null || prompt.isBlank()) {
            return defaultPrompt();
        }
        String key = prompt.trim();
        if (!versions.prompts().contains(key)) {
            throw new RefusedException("PROMPT_NOT_FOUND");
        }
        return key;
    }

    private static String scopeOf(String scope) {
        return scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
    }

    private static String versionOf(String resource) {
        if (resource == null) {
            return null;
        }
        int at = resource.lastIndexOf('@');
        return at >= 0 ? resource.substring(at + 1) : resource;
    }

    private static List<String> errors(String stored) {
        if (stored == null || stored.isBlank()) {
            return List.of();
        }
        return Arrays.stream(stored.split("\n")).map(String::trim).filter(line -> !line.isEmpty()).toList();
    }

    /** A list the operator typed, one value per comma or line, as the registry keeps it (comma separated). */
    private static String list(String typed) {
        if (typed == null || typed.isBlank()) {
            return null;
        }
        String joined = Arrays.stream(typed.split("[,\\n]")).map(String::trim).filter(value -> !value.isEmpty())
                .distinct().collect(Collectors.joining(","));
        return joined.isEmpty() ? null : joined;
    }

    private static String blankAsNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String blankOrReason(String reason) {
        return reason == null || reason.isBlank() ? "" : " (" + reason.trim() + ")";
    }

    private static <T> Supplier<T> orNone(Supplier<T> supplier) {
        return supplier != null ? supplier : () -> null;
    }
}
