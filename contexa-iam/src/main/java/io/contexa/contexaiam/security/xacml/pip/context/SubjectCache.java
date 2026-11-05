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
package io.contexa.contexaiam.security.xacml.pip.context;

import io.contexa.contexacommon.cache.ContexaCacheService;

/** Where the access decisions keep their copies of the users, in the {@link ContexaCacheService}. */
public final class SubjectCache {

    public static final String DOMAIN = "users";

    private static final String BY_ID = "user_details:";
    private static final String BY_NAME = "user_details_name:";

    private SubjectCache() {
    }

    public static String byId(Long userId) {
        return BY_ID + userId;
    }

    public static String byName(String username) {
        return BY_NAME + username;
    }

    /**
     * Takes every copy out of the cache. A copy written before PR-87 holds the user's password hash and stays in Redis
     * until its TTL ends, however it is read; the next request loads a copy without it.
     */
    public static void clear(ContexaCacheService cacheService) {
        cacheService.invalidate(BY_ID + "*");
        cacheService.invalidate(BY_NAME + "*");
    }
}
