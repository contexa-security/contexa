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
package io.contexa.contexacommon.security.bridge.sync;

import org.springframework.lang.Nullable;

/**
 * bridge v2 B5-3 (docs/agent/bridge-v2-B5-2-B5-3-설계안.md 3): what a module that keeps a state under a user copy's name does
 * when the synchronisation makes two copies of one person one. Older versions split a person into a copy per way the
 * person was read; the copy the synchronisation keeps takes over what the other copy held, then the other copy goes.
 * Both calls run in the synchronisation's transaction.
 */
public interface UserCopyMergeContributor {

    /**
     * Why the two copies must stay apart for now, or {@code null} when they may be merged: a state of the user's own that
     * Contexa would have to drop to merge them stops it, and the copies stay until that is resolved.
     */
    @Nullable
    String refusal(String keptUsername, String mergedUsername);

    /** What the merged copy holds under its name becomes the kept copy's, before the merged copy goes. */
    void merge(String keptUsername, String mergedUsername);
}
