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
package io.contexa.contexacore.hcad.semantic;

public enum HcadSemanticEvidenceCacheStatus {

    HIT,
    STALE_HIT,
    CACHE_MISS_SOURCE_AVAILABLE,
    CACHE_MISS_SOURCE_ABSENT,
    CACHE_MISS_SOURCE_UNKNOWN,
    NEGATIVE_CACHE_HIT,
    VERSION_MISMATCH,
    DIMENSION_MISMATCH,
    WARMUP_QUEUED,
    WARMUP_COMPLETED,
    WARMUP_FAILED;

    public boolean usableForScoring() {
        return this == HIT;
    }

    public boolean sourceAbsent() {
        return this == CACHE_MISS_SOURCE_ABSENT || this == NEGATIVE_CACHE_HIT;
    }

    public boolean warmupCandidate() {
        return this == CACHE_MISS_SOURCE_AVAILABLE || this == CACHE_MISS_SOURCE_UNKNOWN;
    }
}
