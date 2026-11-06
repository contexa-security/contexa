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

import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import org.springframework.lang.Nullable;

public interface BridgeUserMirrorSyncService {

    BridgeUserMirrorSyncResult sync(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            RequestContextSnapshot requestContext
    );

    /**
     * The address the application showed for the user since the copy took a real one, which waits until the user
     * proves it; the step-up mails it a code of its own.
     *
     * @param userId the ID of the copy
     * @return the address waiting, or null for none
     */
    @Nullable
    default String pendingEmail(Long userId) {
        return null;
    }

    /**
     * The user proved the address on record (a one-time code mailed there, or a passkey) and then the address waiting,
     * with a code mailed to it: the copy takes that address, if it is still the one waiting.
     *
     * @param userId  the ID of the copy
     * @param address the address the user proved
     * @return whether the copy now has the address that waited
     */
    default boolean confirmPendingEmail(Long userId, String address) {
        return false;
    }
}
