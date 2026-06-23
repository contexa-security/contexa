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
package io.contexa.contexacore.hcad.store;

import java.util.Map;

public interface HCADDataStore {

    Map<Object, Object> getSessionMetadata(String sessionId);

    void saveSessionMetadata(String sessionId, Map<String, Object> metadata);

    boolean isDeviceRegistered(String userId, String device);

    void registerDevice(String userId, String device);

    void recordRequest(String userId, long currentTimeMs);

    int getRecentRequestCount(String userId, long windowStartMs, long currentTimeMs);

    void recordLoginFailure(String userId, String clientIp, long currentTimeMs);

    int getRecentLoginFailureCount(String userId, String clientIp, long windowStartMs, long currentTimeMs);

    boolean isUserRegistered(String userId);

    void registerUser(String userId);

    boolean isMfaVerified(String userId);

    void markMfaVerified(String userId);

    Map<Object, Object> getHcadAnalysis(String userId);

    void saveHcadAnalysis(String userId, Map<String, Object> analysisData);
}
