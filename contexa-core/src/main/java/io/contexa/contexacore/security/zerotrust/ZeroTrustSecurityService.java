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
package io.contexa.contexacore.security.zerotrust;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.context.SecurityContext;

public interface ZeroTrustSecurityService {

    void applyZeroTrustToContext(SecurityContext context, String userId, String sessionId, HttpServletRequest request);

    void invalidateSession(String sessionId, String userId, String reason);

    boolean isSessionInvalidated(String sessionId);

    void cleanupOnLogout(String userId, String sessionId);

    void invalidateAllUserSessions(String userId, String reason);

    default void invalidateDecisionCache(String userId) {}
}
