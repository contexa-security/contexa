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

/**
 * The shadow release of a scope as a shadow run reads it (plan 3.4, 3.9): the release it draws apart from the
 * decision, and the sample share and daily limit its registry row sets ({@code shadow_sample_percent},
 * {@code shadow_daily_limit}). A value the row leaves empty is null, and the configured value runs in its place.
 *
 * @param version       the release the shadow run draws, null for none
 * @param samplePercent the share of requests the shadow run takes, 0 to 100; null for the configured share
 * @param dailyLimit    the shadow runs allowed per UTC day; null for the configured limit
 */
public record PromptShadowRelease(String version, Integer samplePercent, Integer dailyLimit) {

    private static final PromptShadowRelease NONE = new PromptShadowRelease(null, null, null);

    public PromptShadowRelease {
        version = version == null || version.isBlank() ? null : version.trim();
        samplePercent = samplePercent == null ? null : Math.max(0, Math.min(100, samplePercent));
        dailyLimit = dailyLimit == null ? null : Math.max(0, dailyLimit);
    }

    /** No shadow release. */
    public static PromptShadowRelease none() {
        return NONE;
    }

    /** Whether the scope has a shadow release. */
    public boolean present() {
        return version != null;
    }
}
