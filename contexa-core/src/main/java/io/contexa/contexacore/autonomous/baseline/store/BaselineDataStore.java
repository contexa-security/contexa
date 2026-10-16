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

    /** The separator of a tenant and a user in a personal baseline key, the one the context stores use. */
    String TENANT_SEPARATOR = "::";

    /**
     * The key a user's personal baseline is kept under: the user within the tenant ({@code tenant::user}), the user
     * alone without a tenant (W5-10 D9). The same user id in two tenants is two users.
     */
    static String userKey(String tenantId, String userId) {
        return tenantId == null || tenantId.isBlank() || userId == null ? userId
                : tenantId.trim() + TENANT_SEPARATOR + userId;
    }

    BaselineVector getUserBaseline(String userId);

    void saveUserBaseline(String userId, BaselineVector baseline);

    BaselineVector getOrganizationBaseline(String organizationId);

    void saveOrganizationBaseline(String organizationId, BaselineVector baseline);

    Iterable<BaselineVector> listOrganizationBaselines();

    long countUserBaselines();

    /**
     * The result of reading a stored baseline: found, absent, or failed. A failed read is not taken for a missing
     * baseline, so learning never writes a new baseline over one it could not read (W5-8).
     */
    record BaselineRead(State state, BaselineVector baseline) {

        public enum State { FOUND, ABSENT, FAILED }

        public static BaselineRead of(BaselineVector baseline) {
            return new BaselineRead(baseline != null ? State.FOUND : State.ABSENT, baseline);
        }

        public static BaselineRead failed() {
            return new BaselineRead(State.FAILED, null);
        }

        public boolean isFailed() {
            return state == State.FAILED;
        }
    }

    /** Reads a personal baseline telling a failed read from an absent baseline; this default cannot tell a failure. */
    default BaselineRead readUserBaseline(String userId) {
        return BaselineRead.of(getUserBaseline(userId));
    }

    /** Reads an organization baseline telling a failed read from an absent one; this default cannot tell a failure. */
    default BaselineRead readOrganizationBaseline(String organizationId) {
        return BaselineRead.of(getOrganizationBaseline(organizationId));
    }

    /**
     * Removes the personal baseline of a user whose account is deleted, under every tenant, so that a later account
     * with the same name starts without it. Stores that cannot delete must fail loudly rather than keep the baseline
     * silently.
     */
    default void deleteUserBaseline(String userId) {
        throw new UnsupportedOperationException(
                "User baseline deletion is not supported by " + getClass().getSimpleName());
    }

    /** Removes the baseline of one key only: a baseline moved under its tenant leaves its earlier key (W5-10 D9). */
    default void deleteUserBaselineKey(String key) {
        throw new UnsupportedOperationException(
                "User baseline deletion is not supported by " + getClass().getSimpleName());
    }
}
