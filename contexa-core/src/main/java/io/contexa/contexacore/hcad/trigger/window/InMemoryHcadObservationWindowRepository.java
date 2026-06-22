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
package io.contexa.contexacore.hcad.trigger.window;

import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryHcadObservationWindowRepository implements HcadObservationWindowRepository {

    private final Map<String, WindowState> windows = new ConcurrentHashMap<>();

    @Override
    public synchronized HcadObservationWindowLease observe(
            String actorSessionKey,
            HcadRequestObservation observation,
            Duration coalesceWindow,
            Duration observationTtl) {
        if (!StringUtils.hasText(actorSessionKey)) {
            return new HcadObservationWindowLease(true, actorSessionKey, UUID.randomUUID().toString(), 1,
                    families(observation), paths(observation));
        }
        long now = System.currentTimeMillis();
        long windowMs = positiveMillis(coalesceWindow, 1000L);
        WindowState state = windows.get(actorSessionKey);
        boolean acquired = false;
        if (state == null || state.expiresAt <= now) {
            state = new WindowState(UUID.randomUUID().toString(), now + windowMs);
            windows.put(actorSessionKey, state);
            acquired = true;
        }
        state.observations.add(observation);
        return state.lease(actorSessionKey, acquired);
    }

    @Override
    public synchronized Optional<HcadObservationWindowLease> snapshot(String actorSessionKey, String windowId) {
        if (!StringUtils.hasText(actorSessionKey) || !StringUtils.hasText(windowId)) {
            return Optional.empty();
        }
        WindowState state = windows.get(actorSessionKey);
        long now = System.currentTimeMillis();
        if (state == null || state.expiresAt <= now || !windowId.equals(state.windowId)) {
            return Optional.empty();
        }
        return Optional.of(state.lease(actorSessionKey, false));
    }

    @Override
    public synchronized boolean tryAcquireEscalation(String actorSessionKey, String windowId, String anchorSignature) {
        if (!StringUtils.hasText(actorSessionKey)
                || !StringUtils.hasText(windowId)
                || !StringUtils.hasText(anchorSignature)) {
            return false;
        }
        WindowState state = windows.get(actorSessionKey);
        long now = System.currentTimeMillis();
        if (state == null || state.expiresAt <= now || !windowId.equals(state.windowId)) {
            return false;
        }
        if (!state.deepEvaluationCompleted) {
            return false;
        }
        return state.evaluatedAnchorSignatures.add(anchorSignature);
    }

    @Override
    public synchronized void markDeepEvaluationCompleted(String actorSessionKey, String windowId, String anchorSignature) {
        if (!StringUtils.hasText(actorSessionKey) || !StringUtils.hasText(windowId)) {
            return;
        }
        WindowState state = windows.get(actorSessionKey);
        long now = System.currentTimeMillis();
        if (state == null || state.expiresAt <= now || !windowId.equals(state.windowId)) {
            return;
        }
        state.deepEvaluationCompleted = true;
        if (StringUtils.hasText(anchorSignature)) {
            state.evaluatedAnchorSignatures.add(anchorSignature);
        }
    }

    private long positiveMillis(Duration duration, long defaultValue) {
        if (duration == null || duration.isZero() || duration.isNegative()) {
            return defaultValue;
        }
        return Math.max(1L, duration.toMillis());
    }

    private List<String> families(HcadRequestObservation observation) {
        if (observation == null || !StringUtils.hasText(observation.resourceFamily())) {
            return List.of();
        }
        return List.of(observation.resourceFamily());
    }

    private List<String> paths(HcadRequestObservation observation) {
        if (observation == null || !StringUtils.hasText(observation.normalizedPath())) {
            return List.of();
        }
        return List.of(observation.normalizedPath());
    }

    private static final class WindowState {
        private final String windowId;
        private final long expiresAt;
        private final List<HcadRequestObservation> observations = new ArrayList<>();
        private final Set<String> evaluatedAnchorSignatures = new LinkedHashSet<>();
        private boolean deepEvaluationCompleted;

        private WindowState(String windowId, long expiresAt) {
            this.windowId = windowId;
            this.expiresAt = expiresAt;
        }

        private HcadObservationWindowLease lease(String actorSessionKey, boolean acquired) {
            LinkedHashSet<String> families = new LinkedHashSet<>();
            LinkedHashSet<String> paths = new LinkedHashSet<>();
            for (HcadRequestObservation observation : observations) {
                if (observation == null) {
                    continue;
                }
                if (StringUtils.hasText(observation.resourceFamily())) {
                    families.add(observation.resourceFamily());
                }
                if (StringUtils.hasText(observation.normalizedPath())) {
                    paths.add(observation.normalizedPath());
                }
            }
            return new HcadObservationWindowLease(
                    acquired,
                    actorSessionKey,
                    windowId,
                    observations.size(),
                    List.copyOf(families),
                    List.copyOf(paths));
        }
    }
}
