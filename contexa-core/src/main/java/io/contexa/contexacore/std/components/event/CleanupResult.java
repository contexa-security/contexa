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
package io.contexa.contexacore.std.components.event;

import lombok.Getter;

import java.util.List;

@Getter
public class CleanupResult {
    private final List<String> cleanedSessions;
    private final List<String> failedCleanups;
    private final long cleanupTime;
    private final String status;
    private final String errorMessage;

    public CleanupResult(List<String> cleanedSessions, List<String> failedCleanups, long cleanupTime) {
        this.cleanedSessions = cleanedSessions;
        this.failedCleanups = failedCleanups;
        this.cleanupTime = cleanupTime;
        this.status = "SUCCESS";
        this.errorMessage = null;
    }

    private CleanupResult(String errorMessage) {
        this.cleanedSessions = List.of();
        this.failedCleanups = List.of();
        this.cleanupTime = System.currentTimeMillis();
        this.status = "ERROR";
        this.errorMessage = errorMessage;
    }
    public static CleanupResult error(String errorMessage) {
        return new CleanupResult(errorMessage);
    }
}