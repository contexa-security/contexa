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
package io.contexa.contexacore.autonomous.baseline.store;

import io.contexa.contexacommon.security.baseline.BaselineVector;

public interface BaselineDataStore {

    BaselineVector getUserBaseline(String userId);

    void saveUserBaseline(String userId, BaselineVector baseline);

    BaselineVector getOrganizationBaseline(String organizationId);

    void saveOrganizationBaseline(String organizationId, BaselineVector baseline);

    Iterable<BaselineVector> listOrganizationBaselines();

    long countUserBaselines();

    /**
     * Removes the personal baseline of a user whose account is deleted, so that a later account with the same
     * name starts without it. Stores that cannot delete must fail loudly rather than keep the baseline silently.
     */
    default void deleteUserBaseline(String userId) {
        throw new UnsupportedOperationException(
                "User baseline deletion is not supported by " + getClass().getSimpleName());
    }
}
