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
package io.contexa.contexacore.autonomous.context.prompt;

import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class PromptSlotPlanCache implements PromptSlotPlanProvider {

    private static final String CACHE_KEY_SEPARATOR = Character.toString(0x1F);

    private final Map<String, PromptSlotPlan> plans = new ConcurrentHashMap<>();
    private final PromptSlotPlanProvider delegate;

    public PromptSlotPlanCache() {
        this(PromptSlotPlanProvider.unscoped());
    }

    public PromptSlotPlanCache(PromptSlotPlanProvider delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
    }

    @Override
    public PromptSlotPlan planFor(String sectionKey, String labelKey) {
        String normalizedSection = StringUtils.hasText(sectionKey) ? sectionKey.trim() : "";
        String normalizedLabel = StringUtils.hasText(labelKey) ? labelKey.trim() : "";
        if (!StringUtils.hasText(normalizedLabel)) {
            return PromptSlotPlan.unscoped(normalizedSection, normalizedLabel);
        }
        String providerScope = StringUtils.hasText(delegate.cacheScopeKey())
                ? delegate.cacheScopeKey().trim()
                : "UNSCOPED";
        String cacheKey = providerScope + CACHE_KEY_SEPARATOR + normalizedSection + CACHE_KEY_SEPARATOR + normalizedLabel;
        return plans.computeIfAbsent(cacheKey, ignored -> delegate.planFor(normalizedSection, normalizedLabel));
    }

    public PromptSlotPlan planForLabel(String label) {
        return planFor(null, label);
    }

    public int cachedPlanCount() {
        return plans.size();
    }
}
