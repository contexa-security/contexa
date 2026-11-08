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
package io.contexa.contexacore.autonomous.repository;

import org.springframework.lang.Nullable;

import java.util.function.BooleanSupplier;

/**
 * The two views of what SHADOW remembers (see {@link ShadowAwareActionRepository}). It is no {@link ZeroTrustActionRepository}
 * bean itself: a second bean of that type would be a second candidate for everything that enforces a decision, and those
 * must keep the repository alone.
 */
public final class ShadowDecisionMemory {

    private final ZeroTrustActionRepository remembers;
    private final ZeroTrustActionRepository answers;

    public ShadowDecisionMemory(ZeroTrustActionRepository repository, BooleanSupplier enforcing) {
        this.remembers = ShadowAwareActionRepository.always(repository);
        this.answers = ShadowAwareActionRepository.whenNotEnforcing(repository, enforcing);
    }

    /** Where the enforcement handler writes a decision of SHADOW, and where the data of a deleted account is removed. */
    public ZeroTrustActionRepository remembers() {
        return remembers;
    }

    /**
     * What decides whether a user was answered lately (whether a request is analysed): the repository while decisions are
     * enforced, the memory of SHADOW while they are not.
     */
    public ZeroTrustActionRepository answers() {
        return answers;
    }

    /** What answers for the given memory, or for the repository when there is none. */
    public static ZeroTrustActionRepository answersOf(@Nullable ShadowDecisionMemory memory, ZeroTrustActionRepository repository) {
        return memory != null ? memory.answers() : repository;
    }
}
