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
package io.contexa.autoconfigure.identity;

/**
 * The accounts the administrator seed reads and writes: the users and their groups are JPA tables
 * (persistence-ownership.yml, JPA_ONLY), written through their repositories by {@link JpaAdministratorAccounts}.
 */
interface AdministratorAccounts {

    /** Whether a user has the username or the e-mail address. */
    boolean exists(String username, String email);

    /** Creates the administrator, enabled and unlocked, signing in with two steps; returns its id. */
    long create(String username, String email, String encodedPassword, String name);

    boolean groupExists(long groupId);

    /** The user joins the group. */
    void join(long userId, long groupId);
}
