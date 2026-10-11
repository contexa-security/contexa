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
package io.contexa.contexacore.std.components.prompt.bundle;

import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Canonical lifecycle state of a prompt bundle in the registry (version management decision 1). Values of the older
 * vocabularies (registry strings, {@link PromptReleaseStatus}, learning artifact release states) are read through
 * {@link #fromStoredValue(String)}, so gates, SQL and screens classify a release status from this one table. New writes
 * store the canonical name.
 */
public enum PromptBundleState {

    /** In the build with a verified manifest; not executed. */
    AVAILABLE(PromptReleaseStatus.DRAFT, "DRAFT", "COLLECTING", "REVIEW_ONLY"),

    /** Executed on sampled requests and only recorded; the evaluation stage between a draft and a canary. */
    SHADOW(PromptReleaseStatus.EVAL_ONLY, "EVAL_ONLY", "SHADOW_READY", "REPLAY_READY"),

    /** Enforced inside a scope. */
    CANARY(PromptReleaseStatus.CANARY, "ACTIVE_FOR_SCOPE", "CANARY_READY"),

    /** Enforced by default. */
    ACTIVE(PromptReleaseStatus.PRODUCTION, "PRODUCTION", "PROMOTED", "RELEASED", "CURRENT", "RUNTIME_APPROVED",
            "PRODUCTION_APPROVED"),

    /** No longer selectable; kept as a rollback target and as a record. */
    DEPRECATED(PromptReleaseStatus.ROLLED_BACK, "ROLLED_BACK", "WITHDRAWN", "KILL_SWITCH_ACTIVE"),

    /** Removed from the build; only the record is kept. */
    RETIRED(PromptReleaseStatus.RETIRED);

    private static final Map<String, PromptBundleState> BY_STORED_VALUE = byStoredValue();

    private final PromptReleaseStatus releaseStatus;
    private final List<String> legacyValues;

    PromptBundleState(PromptReleaseStatus releaseStatus, String... legacyValues) {
        this.releaseStatus = releaseStatus;
        this.legacyValues = List.of(legacyValues);
    }

    /**
     * Reads a stored release status of any known vocabulary. Unknown or blank values have no canonical state and are
     * treated as not executing.
     */
    public static Optional<PromptBundleState> fromStoredValue(String storedValue) {
        if (storedValue == null || storedValue.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(BY_STORED_VALUE.get(storedValue.trim().toUpperCase(Locale.ROOT)));
    }

    public static PromptBundleState fromReleaseStatus(PromptReleaseStatus releaseStatus) {
        for (PromptBundleState state : values()) {
            if (state.releaseStatus == releaseStatus) {
                return state;
            }
        }
        throw new IllegalArgumentException("No canonical bundle state for release status " + releaseStatus);
    }

    /** True for a stored release status whose bundle is enforced at runtime (by default or inside a scope). */
    public static boolean isExecuting(String storedValue) {
        return fromStoredValue(storedValue).map(PromptBundleState::executing).orElse(false);
    }

    /** True for a stored release status that reads as the given state. */
    public static boolean is(String storedValue, PromptBundleState state) {
        return fromStoredValue(storedValue).map(state::equals).orElse(false);
    }

    /** The canonical name of a stored release status, or the trimmed value itself when it belongs to no vocabulary. */
    public static String canonicalName(String storedValue) {
        return fromStoredValue(storedValue)
                .map(Enum::name)
                .orElse(storedValue == null ? null : storedValue.trim());
    }

    /**
     * The SQL list of every stored value (canonical and older names, upper case) of the given states, for a condition
     * such as {@code upper(release_status) in (...)}. The values are fixed constants of this enum.
     */
    public static String sqlList(PromptBundleState... states) {
        return Arrays.stream(states)
                .flatMap(state -> state.storedValues().stream())
                .map(value -> "'" + value + "'")
                .collect(Collectors.joining(", "));
    }

    public boolean executing() {
        return this == ACTIVE || this == CANARY;
    }

    /** The release status of the descriptor vocabulary that has this meaning. */
    public PromptReleaseStatus releaseStatus() {
        return releaseStatus;
    }

    /** The canonical name first, then every older name that reads as this state. */
    public List<String> storedValues() {
        List<String> values = new ArrayList<>();
        values.add(name());
        legacyValues.stream().filter(value -> !values.contains(value)).forEach(values::add);
        return Collections.unmodifiableList(values);
    }

    private static Map<String, PromptBundleState> byStoredValue() {
        Map<String, PromptBundleState> map = new HashMap<>();
        for (PromptBundleState state : values()) {
            for (String value : state.storedValues()) {
                PromptBundleState previous = map.put(value, state);
                if (previous != null && previous != state) {
                    throw new IllegalStateException("Release status " + value + " maps to " + previous + " and " + state);
                }
            }
        }
        return Map.copyOf(map);
    }
}
