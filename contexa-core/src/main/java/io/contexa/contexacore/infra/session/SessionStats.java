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

public class SessionStats {
    private final long activeSessions;
    private final long totalSessionsCreated;
    private final long sessionCollisions;
    private final double averageSessionDuration;
    private final String repositoryType;

    public SessionStats(long activeSessions, long totalSessionsCreated,
                        long sessionCollisions, double averageSessionDuration,
                        String repositoryType) {
        this.activeSessions = activeSessions;
        this.totalSessionsCreated = totalSessionsCreated;
        this.sessionCollisions = sessionCollisions;
        this.averageSessionDuration = averageSessionDuration;
        this.repositoryType = repositoryType;
    }

    public long getActiveSessions() { return activeSessions; }
    public long getTotalSessionsCreated() { return totalSessionsCreated; }
    public long getSessionCollisions() { return sessionCollisions; }
    public double getAverageSessionDuration() { return averageSessionDuration; }
    public String getRepositoryType() { return repositoryType; }

    @Override
    public String toString() {
        return String.format("SessionStats{type=%s, active=%d, total=%d, collisions=%d, avgDuration=%.2fs}",
                repositoryType, activeSessions, totalSessionsCreated, sessionCollisions, averageSessionDuration);
    }
}
