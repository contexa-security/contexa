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
package io.contexa.contexacore.verification.evidence;

import java.time.Instant;
import java.util.Optional;

/**
 * What a store knows of the packages around a sealed package, which the package alone cannot tell (Q-21): since when the
 * packages are signed, and whether the package it was sealed after is still kept.
 */
public interface SealedEvidenceChain {

    /** When the oldest signed package kept was captured; empty while no package is signed. */
    Optional<Instant> signedSince();

    /** Whether a package with the hash this stored package names as its previous one is kept before it. */
    boolean previousKept(SealedEvidencePackage pkg);

    /**
     * The latest capture time among the package kept right before this stored one and the signed package kept right
     * before it; empty when none is kept. A package without a signature can be dated back, a signed one cannot.
     */
    Optional<Instant> capturedBefore(SealedEvidencePackage pkg);
}
