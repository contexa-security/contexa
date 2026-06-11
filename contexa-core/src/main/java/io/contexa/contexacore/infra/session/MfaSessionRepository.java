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
package io.contexa.contexacore.infra.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.Nullable;

import java.time.Duration;

public interface MfaSessionRepository {

    void storeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response);

    @Nullable
    String getSessionId(HttpServletRequest request);

    void removeSession(String sessionId, HttpServletRequest request, @Nullable HttpServletResponse response);

    void refreshSession(String sessionId);

    boolean existsSession(String sessionId);

    void setSessionTimeout(Duration timeout);

    String getRepositoryType();

    String generateUniqueSessionId(@Nullable String baseId, HttpServletRequest request);

    boolean isSessionIdUnique(String sessionId);

    String resolveSessionIdCollision(String originalId, HttpServletRequest request, int maxAttempts);

    boolean isValidSessionIdFormat(String sessionId);

    boolean supportsDistributedSync();
}