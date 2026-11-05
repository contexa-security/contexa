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
 * How an application tells Contexa a user's mail address (Q-1), when its signed-in user has no {@code getEmail()}: a
 * bean of this type. The address is where a verification code goes, so a user the application knows an address of can
 * answer a CHALLENGE. An address the signed-in user carries comes first, and an address an administrator entered in the
 * console stands. It is asked on a request of a user without a real address, so an answer should be cheap.
 */
@FunctionalInterface
public interface BridgeUserEmailProvider {

    /**
     * The mail address of the user the application signed in.
     *
     * @param principalId the application's name of the user
     * @return the address, or null when the application has none
     */
    @Nullable
    String emailOf(String principalId);
}
