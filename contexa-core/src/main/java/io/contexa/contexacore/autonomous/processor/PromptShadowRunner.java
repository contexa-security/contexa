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
package io.contexa.contexacore.autonomous.processor;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptSections;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRelease;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRun;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * W6-9 (P6-CHANGE-6): the shadow run of a prompt release. On a sampled request whose scope has a shadow release, the
 * event as it came is copied before the decision (its own event and request ids, the candidate release chosen, marked
 * as a shadow run and as a shadow decision boundary); after the decision the copy is analysed apart on its own
 * executor, within a daily call cap, and sealed as the SHADOW stage. The copy never reaches the enforcement handler,
 * so nothing is enforced or learned; a marked event adds nothing to the session context and makes no other shadow run.
 *
 * <p>Plan 3.9: the candidate is a version of the database ({@code v2.0}), or a bundle this build runs. A candidate that
 * is the version the request's decision runs is not run again. The registry row of the shadow release sets its sample
 * share and its daily limit; where it sets none, the configured ones run.
 */
@Slf4j
public class PromptShadowRunner {

    /** The event metadata mark of a shadow run's copy. */
    public static final String SHADOW_RUN = PromptShadowRun.MARK;
    static final String BUNDLE_VERSION = SecurityDecisionPromptSections.EVENT_BUNDLE_VERSION;
    static final String BUNDLE_SOURCE = SecurityDecisionPromptSections.EVENT_BUNDLE_SOURCE;
    static final String BUNDLE_CONTENT_HASH = SecurityDecisionPromptSections.EVENT_BUNDLE_CONTENT_HASH;
    private static final String SHADOW_STAGE = "SHADOW";

    private final PromptBundleSelector selector;
    private final Function<SecurityEvent, PromptGovernanceResolutionContext> resolution;
    private final Executor executor;
    private final BiConsumer<SecurityEvent, ProcessingResult> sealer;
    private final int samplePercent;
    private final int dailyCallCap;
    private final Clock clock;
    private final Map<String, Integer> calls = new HashMap<>();
    /** The daily limit of each release, as its registry row set it when its last copy was made. */
    private final Map<String, Integer> limits = new ConcurrentHashMap<>();
    private LocalDate day;

    /**
     * @param samplePercent the share of requests a shadow release runs on when its registry row sets none
     * @param dailyCallCap  the shadow runs of a release allowed per UTC day when its registry row sets none
     */
    public PromptShadowRunner(PromptBundleSelector selector,
                              Function<SecurityEvent, PromptGovernanceResolutionContext> resolution, Executor executor,
                              BiConsumer<SecurityEvent, ProcessingResult> sealer, int samplePercent, int dailyCallCap,
                              Clock clock) {
        this.selector = Objects.requireNonNull(selector, "selector");
        this.resolution = Objects.requireNonNull(resolution, "resolution");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.sealer = Objects.requireNonNull(sealer, "sealer");
        this.samplePercent = Math.max(0, Math.min(100, samplePercent));
        this.dailyCallCap = Math.max(0, dailyCallCap);
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Whether the event is a shadow run's copy. */
    public static boolean isShadow(SecurityEvent event) {
        return PromptShadowRun.isShadow(event);
    }

    /**
     * The copy a shadow run analyses, taken before the decision writes into the event; null when the event is a copy,
     * its scope has no shadow release that runs, it is outside the release's sample, or the release is the version the
     * decision runs.
     */
    public SecurityEvent prepare(SecurityEvent event) {
        if (event == null || isShadow(event) || event.getEventId() == null) {
            return null;
        }
        PromptGovernanceResolutionContext context;
        PromptShadowRelease candidate;
        try {
            context = resolution.apply(event);
            candidate = selector.shadowRelease(context, subjectKey(event));
        } catch (RuntimeException e) {
            log.error("[ShadowRun] Shadow release could not be read: eventId={}", event.getEventId(), e);
            return null;
        }
        if (candidate == null || !candidate.present()) {
            return null;
        }
        int share = candidate.samplePercent() != null ? candidate.samplePercent() : samplePercent;
        if (share == 0 || Math.floorMod(event.getEventId().hashCode(), 100) >= share) {
            return null;
        }
        // A bundle this build does not run would draw the decision's own prompt in the shadow. A version is read from
        // the version table, where the selector found it shown.
        boolean version = PromptBundleCatalog.isVersionName(candidate.version());
        if (!version && SecurityDecisionPromptBundles.find(candidate.version()).isEmpty()) {
            return null;
        }
        String deciding = decidingVersion(event, context);
        if (sameRelease(candidate.version(), deciding)) {
            log.debug("[ShadowRun] The shadow release {} is the version the decision runs; no shadow run: eventId={}",
                    candidate.version(), event.getEventId());
            return null;
        }
        String drawn = version ? PromptVersionNames.name(PromptVersionNames.number(candidate.version()).getAsInt())
                : candidate.version();
        limits.put(drawn, candidate.dailyLimit() != null ? candidate.dailyLimit() : dailyCallCap);
        Map<String, Object> metadata = copyOf(event.getMetadata() != null ? event.getMetadata() : Map.of());
        // Plan 3.4: the copy's decision is drawn with the version fixed on it, as every decision is; the prompt reads the
        // content hash of that version again.
        metadata.put(BUNDLE_VERSION, drawn);
        metadata.put(BUNDLE_SOURCE, PromptBundleSelectionSource.SHADOW.name());
        metadata.remove(BUNDLE_CONTENT_HASH);
        metadata.put(SHADOW_RUN, true);
        metadata.put("decisionBoundaryMode", SHADOW_STAGE);
        // N-SHD-1: the copy names the request its decision is sealed under, so its seal is paired with the decision's.
        metadata.put(PromptShadowRun.ORIGINAL_REQUEST_ID, PromptShadowRun.requestIdOf(event));
        metadata.put("requestId", "shadow-" + UUID.randomUUID());
        // The decision's identities key its prompt trace and its seal; the copy is traced and sealed by its own request id.
        metadata.remove(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY);
        metadata.remove("correlationId");
        return SecurityEvent.builder()
                .eventId(event.getEventId() + ":shadow")
                .source(event.getSource())
                .timestamp(event.getTimestamp())
                .severity(event.getSeverity())
                .description(event.getDescription())
                .sourceIp(event.getSourceIp())
                .userId(event.getUserId())
                .userName(event.getUserName())
                .sessionId(event.getSessionId())
                .userAgent(event.getUserAgent())
                .metadata(metadata)
                .blocked(false)
                .build();
    }

    /**
     * Analyses the copy apart after the decision and seals it as the SHADOW stage, within the daily limit of its
     * release.
     */
    public void run(SecurityEvent copy, Function<SecurityEvent, ProcessingResult> analysis) {
        if (copy == null) {
            return;
        }
        String release = releaseOf(copy);
        if (!takeCall(release, limits.getOrDefault(release, dailyCallCap))) {
            return;
        }
        executor.execute(() -> {
            try {
                ProcessingResult result = analysis.apply(copy);
                if (result == null) {
                    return;
                }
                result.addAnalysisData("decisionAppliedStage", SHADOW_STAGE);
                sealer.accept(copy, result);
            } catch (RuntimeException e) {
                log.error("[ShadowRun] Shadow run failed: eventId={}", copy.getEventId(), e);
            }
        });
    }

    /**
     * The version the request's decision runs: the one its event already names, else the one the selector chooses for
     * it (its label, its canary, the setting or the newest Contexa version); null when nothing names one.
     */
    private String decidingVersion(SecurityEvent event, PromptGovernanceResolutionContext context) {
        Object pinned = event.getMetadata() != null ? event.getMetadata().get(BUNDLE_VERSION) : null;
        if (pinned != null && StringUtils.hasText(pinned.toString())) {
            return pinned.toString().trim();
        }
        try {
            PromptBundleSelection chosen = selector.select(context, subjectKey(event));
            return chosen != null ? chosen.bundleVersion() : null;
        } catch (RuntimeException e) {
            log.error("[ShadowRun] The version the decision runs could not be read: eventId={}", event.getEventId(), e);
            return null;
        }
    }

    /** Whether two names name the same release: the same version number, or the same bundle name. */
    static boolean sameRelease(String candidate, String deciding) {
        if (candidate == null || deciding == null) {
            return false;
        }
        OptionalInt left = PromptVersionNames.number(candidate);
        OptionalInt right = PromptVersionNames.number(deciding);
        if (left.isPresent() || right.isPresent()) {
            return left.equals(right);
        }
        return candidate.trim().equals(deciding.trim());
    }

    /** The requester a canary share is drawn by, as the decision draws it: the user, else the session, else the event. */
    private static String subjectKey(SecurityEvent event) {
        return StringUtils.hasText(event.getUserId()) ? event.getUserId()
                : StringUtils.hasText(event.getSessionId()) ? event.getSessionId()
                : event.getEventId();
    }

    private static String releaseOf(SecurityEvent copy) {
        Object release = copy.getMetadata() != null ? copy.getMetadata().get(BUNDLE_VERSION) : null;
        return release != null ? release.toString() : "";
    }

    /**
     * The copy's own maps and lists, so the decision and its post-processing on one thread and the shadow analysis on
     * another never share one; other values are kept as they are.
     */
    private static Map<String, Object> copyOf(Map<?, ?> source) {
        Map<String, Object> copy = new LinkedHashMap<>();
        source.forEach((key, value) -> copy.put(String.valueOf(key), copyValue(value)));
        return copy;
    }

    private static Object copyValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            return copyOf(map);
        }
        if (value instanceof Set<?> set) {
            Set<Object> copy = new LinkedHashSet<>();
            set.forEach(item -> copy.add(copyValue(item)));
            return copy;
        }
        if (value instanceof Collection<?> collection) {
            List<Object> copy = new ArrayList<>(collection.size());
            collection.forEach(item -> copy.add(copyValue(item)));
            return copy;
        }
        return value;
    }

    /** Takes one call of the release's day; each release is counted against its own limit. */
    private synchronized boolean takeCall(String release, int limit) {
        LocalDate today = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
        if (!today.equals(day)) {
            day = today;
            calls.clear();
        }
        int taken = calls.getOrDefault(release, 0);
        if (taken >= limit) {
            return false;
        }
        calls.put(release, taken + 1);
        return true;
    }
}
