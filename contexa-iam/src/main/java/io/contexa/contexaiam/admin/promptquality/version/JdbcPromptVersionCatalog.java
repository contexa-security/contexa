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

import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionCatalog;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.function.Supplier;

/**
 * The versions of the database as the release machinery reads them (plan 3.9): the release gate, the rollback, the
 * runnability of a release and the replay of a sealed decision read the version table here. The version a scope
 * decides with is the one the decision's selector chooses for a request without a requester, which no canary takes
 * (plan 3.4: the label of the scope, else of the platform, else the setting, else the newest Contexa version).
 */
public class JdbcPromptVersionCatalog implements PromptVersionCatalog {

    private static final Logger log = LoggerFactory.getLogger(JdbcPromptVersionCatalog.class);
    /** The stored values of a release used for decisions, of every vocabulary (decision 1). */
    private static final String ACTIVE_STATES = PromptBundleState.sqlList(PromptBundleState.ACTIVE);
    /** The workflow state of a transition the release gate applied. */
    private static final String APPLIED = "APPROVED_AND_APPLIED";

    private final PromptVersionService versions;
    private final Supplier<JdbcTemplate> jdbc;
    private final Supplier<PromptBundleSelector> decisions;

    /**
     * @param decisions the selector of the decisions (the version resolver); a supplier of null when there is none
     */
    public JdbcPromptVersionCatalog(PromptVersionService versions, Supplier<JdbcTemplate> jdbc,
                                    Supplier<PromptBundleSelector> decisions) {
        this.versions = Objects.requireNonNull(versions, "versions");
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.decisions = decisions != null ? decisions : () -> null;
    }

    @Override
    public List<Entry> versions(String scope, String prompt) {
        if (prompt == null || prompt.isBlank()) {
            return List.of();
        }
        return versions.list(scope, prompt.trim(), true).stream()
                .map(record -> new Entry(record.scope(), record.prompt(), record.number(), record.contentHash(),
                        record.basedOnNumber(), record.provider(), record.hidden()))
                .toList();
    }

    @Override
    public Optional<Entry> find(String scope, String prompt, String name) {
        OptionalInt number = PromptVersionNames.number(name);
        if (number.isEmpty() || prompt == null || prompt.isBlank()) {
            return Optional.empty();
        }
        return versions.find(scope, prompt.trim(), number.getAsInt())
                .map(record -> new Entry(record.scope(), record.prompt(), record.number(), record.contentHash(),
                        record.basedOnNumber(), record.provider(), record.hidden()));
    }

    @Override
    public Optional<AssembledPrompt> assembled(String scope, String prompt, String name) {
        OptionalInt number = PromptVersionNames.number(name);
        if (number.isEmpty() || prompt == null || prompt.isBlank()) {
            return Optional.empty();
        }
        return versions.assembled(scope, prompt.trim(), number.getAsInt());
    }

    @Override
    public Optional<String> deciding(String scope, String prompt) {
        PromptBundleSelector selector = decisions.get();
        if (selector == null || prompt == null || prompt.isBlank()) {
            return Optional.empty();
        }
        String scopeName = scope != null && !scope.isBlank() ? scope.trim() : PLATFORM_SCOPE;
        String templateKey = versions.target(prompt.trim()).map(PromptVersionService.RegistryTarget::templateKey)
                .orElse(null);
        PromptBundleSelection selection;
        try {
            selection = selector.select(new PromptGovernanceResolutionContext(scopeName, prompt.trim(), templateKey,
                    PLATFORM_SCOPE.equals(scopeName) ? null : scopeName, null, null, null, Map.of()), null);
        }
        catch (RuntimeException failure) {
            log.error("[PromptVersion] The version {} decides with in {} could not be read", prompt, scopeName, failure);
            return Optional.empty();
        }
        String name = selection != null ? selection.bundleVersion() : null;
        return PromptVersionNames.number(name).stream().mapToObj(PromptVersionNames::name).findFirst();
    }

    @Override
    public boolean trialFinished(String scope, String prompt, String name) {
        OptionalInt number = PromptVersionNames.number(name);
        if (number.isEmpty() || prompt == null || prompt.isBlank()) {
            return false;
        }
        Integer done = jdbc.get().queryForObject("select count(*) from ctxa_prompt_version_trial where registry_scope = ?"
                        + " and prompt_key = ? and candidate_number = ? and status = ?", Integer.class,
                scope != null && !scope.isBlank() ? scope.trim() : PLATFORM_SCOPE, prompt.trim(), number.getAsInt(),
                PromptVersionTrials.DONE);
        return done != null && done > 0;
    }

    /**
     * Plan 3.4: a version was used for decisions in the scope when it decides there now, when the release gate applied
     * it as the version used for decisions there, when a rollback went to it there and was not refused, or when it was
     * the version deciding there as the gate started another version, which the rollback ledger keeps as the target to
     * go back to. That last record also holds a version that decided without a label: the one the setting names, or
     * the newest Contexa version. A canary alone is not a use for decisions.
     */
    @Override
    public boolean usedForDecisions(String scope, String prompt, String name) {
        OptionalInt number = PromptVersionNames.number(name);
        if (number.isEmpty() || prompt == null || prompt.isBlank()) {
            return false;
        }
        String scopeName = scope != null && !scope.isBlank() ? scope.trim() : PLATFORM_SCOPE;
        String version = PromptVersionNames.name(number.getAsInt());
        if (deciding(scopeName, prompt).filter(version::equals).isPresent()) {
            return true;
        }
        Integer recorded = jdbc.get().queryForObject("select (select count(*) from"
                        + " ctxa_prompt_governance_release_workflow where registry_scope = ? and prompt_key = ? and"
                        + " prompt_version = ? and upper(target_release_status) in (" + ACTIVE_STATES + ") and"
                        + " workflow_state = ?) + (select count(*) from ctxa_prompt_governance_rollback_execution where"
                        + " registry_scope = ? and prompt_key = ? and to_version = ? and status in (?, ?, ?)) + (select"
                        + " count(*) from ctxa_prompt_governance_rollback_ledger where registry_scope = ? and prompt_key"
                        + " = ? and rollback_target_prompt_version = ?)", Integer.class,
                scopeName, prompt.trim(), version, APPLIED,
                scopeName, prompt.trim(), version, PromptBundleRollbackService.EXECUTED,
                PromptBundleRollbackService.AWAITING_APPROVAL, PromptBundleRollbackService.APPROVED,
                scopeName, prompt.trim(), version);
        return recorded != null && recorded > 0;
    }
}
