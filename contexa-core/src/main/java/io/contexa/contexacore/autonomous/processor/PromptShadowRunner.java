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
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRun;
import lombok.extern.slf4j.Slf4j;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.function.BiConsumer;
import java.util.function.Function;

/**
 * W6-9 (P6-CHANGE-6): the shadow run of a prompt bundle. On a sampled request whose scope has a shadow release, the
 * event as it came is copied before the decision (its own event and request ids, the candidate bundle chosen, marked
 * as a shadow run and as a shadow decision boundary); after the decision the copy is analysed apart on its own
 * executor, within a daily call cap, and sealed as the SHADOW stage. The copy never reaches the enforcement handler,
 * so nothing is enforced or learned; a marked event adds nothing to the session context and makes no other shadow run.
 */
@Slf4j
public class PromptShadowRunner {

    /** The event metadata mark of a shadow run's copy. */
    public static final String SHADOW_RUN = PromptShadowRun.MARK;
    static final String BUNDLE_VERSION = "promptBundleSelection.version";
    static final String BUNDLE_SOURCE = "promptBundleSelection.source";
    private static final String SHADOW_STAGE = "SHADOW";

    private final PromptBundleSelector selector;
    private final Function<SecurityEvent, PromptGovernanceResolutionContext> resolution;
    private final Executor executor;
    private final BiConsumer<SecurityEvent, ProcessingResult> sealer;
    private final int samplePercent;
    private final int dailyCallCap;
    private final Clock clock;
    private LocalDate day;
    private int calls;

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
     * outside the sample, or its scope has no shadow release.
     */
    public SecurityEvent prepare(SecurityEvent event) {
        if (event == null || isShadow(event) || samplePercent == 0 || event.getEventId() == null
                || Math.floorMod(event.getEventId().hashCode(), 100) >= samplePercent) {
            return null;
        }
        PromptBundleSelection candidate;
        try {
            candidate = selector.shadow(resolution.apply(event), event.getUserId());
        } catch (RuntimeException e) {
            log.error("[ShadowRun] Shadow release could not be read: eventId={}", event.getEventId(), e);
            return null;
        }
        // A release of a bundle this build does not run would draw the decision's own bundle in the shadow.
        if (candidate == null || SecurityDecisionPromptBundles.find(candidate.bundleVersion()).isEmpty()) {
            return null;
        }
        Map<String, Object> metadata = copyOf(event.getMetadata() != null ? event.getMetadata() : Map.of());
        metadata.put(BUNDLE_VERSION, candidate.bundleVersion());
        metadata.put(BUNDLE_SOURCE, PromptBundleSelectionSource.SHADOW.name());
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

    /** Analyses the copy apart after the decision and seals it as the SHADOW stage, within the daily call cap. */
    public void run(SecurityEvent copy, Function<SecurityEvent, ProcessingResult> analysis) {
        if (copy == null || !takeCall()) {
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

    private synchronized boolean takeCall() {
        LocalDate today = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
        if (!today.equals(day)) {
            day = today;
            calls = 0;
        }
        if (calls >= dailyCallCap) {
            return false;
        }
        calls++;
        return true;
    }
}
