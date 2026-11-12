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
package io.contexa.contexacommon.security;

/** Paths of Contexa's console that modules which do not know each other have to agree on. */
public final class ContexaConsolePaths {

    /**
     * Where the signed-in owner, and an account whose password expired, change a password. An expired password cannot
     * sign in, so this is reached before any sign-in.
     */
    public static final String PASSWORD_CHANGE = "/contexa/password-change";

    /**
     * The session attribute that names the account for {@link #PASSWORD_CHANGE} after a sign-in with an expired
     * password, so that the name is not carried in the page's address.
     */
    public static final String PASSWORD_CHANGE_USERNAME_ATTRIBUTE = "io.contexa.passwordChange.username";

    private ContexaConsolePaths() {
    }
}
