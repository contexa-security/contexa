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

import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.VersionDecisions;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * What the prompt version screens read and send (plan 3.10). Codes travel as they are (a state, a mark, a problem
 * code); the screens name them in the reader's language. A value that is not known is null, never zero.
 */
public final class PromptVersionConsoleDtos {

    private PromptVersionConsoleDtos() {
    }

    // ----- the list (screen 1) -----

    /** A prompt the screens can choose, and whether it is the security decision ("used for decisions"). */
    public record PromptChoice(String key, boolean decision) {
    }

    /**
     * The version decisions run now: the label of the screen, else the setting, else the newest Contexa version.
     *
     * @param source REGISTRY (the label), CONFIGURATION, BUILD_DEFAULT, or NONE when no version is registered
     */
    public record Used(String version, String title, String source, Instant since, String basedOn, int changes,
                       String createdBy) {
    }

    public record Counts(int total, int contexa, int organization, int hidden) {
    }

    /** What runs beside the version in use: a canary, a shadow, and the trial that has not finished. */
    public record Running(String canary, Integer canaryPercent, String canaryTenants, String canaryPaths, String shadow,
                          Integer shadowSamplePercent, Integer shadowDailyLimit, PromptVersionTrials.Trial trial) {
    }

    /** A product version newer than the one the version in use stands on. */
    public record NewProduct(String version, int number, String usedVersion, String usedBase) {
    }

    /**
     * One version of the list.
     *
     * @param state USED, CANARY, SHADOW, UNUSED or HIDDEN
     */
    public record VersionRow(int number, String name, String title, String description, String provider, String origin,
                             String originName, String basedOn, Instant createdAt, String createdBy, boolean hidden,
                             String state, boolean fromDocument, int changes) {
    }

    public record ListView(String scope, List<String> scopes, String prompt, List<PromptChoice> prompts,
                           boolean decisionPrompt, boolean trialsOffered, boolean writable, Used used, Counts counts,
                           Running running, NewProduct newProduct, List<VersionRow> versions) {
    }

    // ----- a version (screen 2) -----

    public record ItemView(String key, String text, String use) {
    }

    /**
     * One part of a version, against its base.
     *
     * @param list SYSTEM or USER
     * @param mark LOCKED (Contexa's, unchanged), DEFAULT (a part of a product version), SAME (as the base), CHANGED,
     *             DELETED (where it stood in the base), ADDED or INCLUDED (a prepared part put in)
     * @param when the condition a conditional part is drawn under; null when always
     */
    public record PartView(int position, String list, String key, String title, String group, boolean locked,
                           String when, String mark, String text, String baseText, List<ItemView> items) {
    }

    /**
     * The finished prompt: the system text the version draws, the output format, and the user prompt of the latest
     * sealed decision with the version it was drawn with.
     */
    public record Preview(String system, String format, String user, String requestId, Instant capturedAt,
                          String drawnWith, boolean drawnWithThisVersion, List<PartView> addedBlocks) {
    }

    public record Size(int systemTokens, Integer baseSystemTokens) {
    }

    public record VersionView(String scope, String prompt, boolean decisionPrompt, boolean trialsOffered,
                              boolean writable, VersionRow version, String contentHash, String baseName,
                              Map<String, Integer> changes, List<PartView> system, List<PartView> user, Preview preview,
                              Size size, VersionDecisions decisions, boolean canBase) {
    }

    // ----- a new version (screen 3) -----

    /**
     * One part a new version can keep, change, delete or add after.
     *
     * @param productText the text of the part in the product version, for "back to the product default"
     * @param editable    whether the organization may change or delete it
     */
    public record DraftPart(String list, String key, String title, String group, boolean locked, boolean prepared,
                            String when, String text, String productText, List<ItemView> items, boolean editable) {
    }

    /** A change of the version in use carried onto a newer product version, and whether it can be. */
    public record Carried(String list, String key, String action, String title, String text, String addAfter,
                          boolean movable) {
    }

    public record Draft(String scope, String prompt, boolean decisionPrompt, int base, String baseName,
                        String baseTitle, String baseHash, boolean baseFromDocument, String nextName,
                        List<DraftPart> system, List<DraftPart> user, List<DraftPart> prepared,
                        List<String> systemPlaces, List<String> userPlaces, List<Carried> carried, String carriedFrom,
                        int baseSystemTokens) {
    }

    /** One change of the form: CHANGE, DELETE, ADD or INCLUDE. */
    public record FormPart(String key, String action, String title, String text, String addAfter) {
    }

    /** What the screen sends to check or to save a new version. */
    public record DraftForm(String prompt, Integer base, String title, String description, List<FormPart> system,
                            List<FormPart> user, Boolean useNow, String reason) {
    }

    public record ProblemView(String code, String where, String detail) {
    }

    /**
     * One of the four checks before saving (plan 3.5).
     *
     * @param key LOCKED, PLACES, CONTENT or LENGTH
     */
    public record CheckRow(String key, boolean passed) {
    }

    /**
     * What the checks found.
     *
     * @param estimatedDeltaMs how much longer (or shorter) a decision is estimated to take; null without recent
     *                         decisions to estimate from
     */
    public record CheckView(boolean passed, List<CheckRow> checks, List<ProblemView> problems, int baseSystemTokens,
                            int systemTokens, Long estimatedDeltaMs, Integer contextTokens) {
    }

    /** A saved version, and the receipt of using it for decisions when the screen asked to. */
    public record Created(int number, String name, String contentHash, boolean made, Receipt used) {
    }

    // ----- labels -----

    /** What a label move did: applied or not, with the gate's blockers when not. */
    public record Receipt(boolean applied, String version, String previous, String gateState, List<String> blockers) {
    }

    /** What the confirmation of "use for decisions" shows: the version in use now, the gate's answer, the trials. */
    public record UseCheck(String version, String current, boolean ready, List<String> blockers,
                           PromptVersionTrials.Trial latestTrial) {
    }

    // ----- the trials (screen 4) -----

    public record TrialStart(String scope, String prompt, boolean offered, List<VersionRow> versions, String current,
                             List<Integer> counts, List<PromptVersionTrials.Trial> recent) {
    }

    public record TrialView(String scope, String prompt, PromptVersionTrials.Result result, boolean writable) {
    }

    /** On how many requests a decision action and a shadow action came together. */
    public record ActionChange(String decisionAction, String shadowAction, long requests) {
    }

    /** A shadow run paired with the decision of its request. */
    public record ShadowCase(String requestId, Instant capturedAt, String shadowVersion, String shadowAction,
                             String decisionVersion, String decisionAction) {
    }

    /** The shadow runs of the period paired with their decisions ("results of running alongside"). */
    public record ShadowResults(String shadow, Instant from, Instant to, long shadows, long paired, long changed,
                                List<ActionChange> changes, List<ShadowCase> cases) {
    }

    // ----- advanced (screen 5) -----

    public record ScanRow(String node, String folder, Instant scannedAt, int documents, int registered,
                          List<String> errors) {
    }

    /** The document folder: its setting, whether it is read, the latest reads per node, and its latest version. */
    public record FolderView(String setting, boolean enabled, List<ScanRow> scans, VersionRow lastRegistered) {
    }

    public record HistoryRow(Instant at, String actor, String action, String version, String reason) {
    }

    public record RollbackRow(String executionKey, String from, String to, String actor, String reason,
                              boolean emergency, String status, LocalDateTime executedAt, String approvedBy,
                              LocalDateTime approvedAt) {
    }

    public record AdvancedView(String scope, String prompt, boolean decisionPrompt, boolean writable, FolderView folder,
                               Running running, String current, List<VersionRow> versions, List<HistoryRow> history,
                               List<RollbackRow> rollbacks, List<Integer> canaryPercents, List<Integer> shadowPercents) {
    }
}
