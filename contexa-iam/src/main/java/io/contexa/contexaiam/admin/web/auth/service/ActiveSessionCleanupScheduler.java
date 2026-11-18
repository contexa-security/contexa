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
package io.contexa.contexaiam.admin.web.auth.service;

import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Duration;

/**
 * K73: the tracked sessions that ended without a word go from the active ones, and the ended ones go once their
 * retention ends. A session that ends on a running node is marked by its HTTP session's end (ActiveSessionEndListener);
 * the sessions of a node that stopped never end that way, so a session no request reached for longer than the HTTP
 * session's idle limit, and the time its row may lag behind its last request, is no longer counted active.
 */
@Slf4j
public class ActiveSessionCleanupScheduler {

    /** The servlet container's default idle limit of an HTTP session. */
    public static final Duration DEFAULT_IDLE_LIMIT = Duration.ofMinutes(30);
    /** What a session's row may lag behind its last request: tracked at most every 30 seconds, written every 60. */
    static final Duration TRACKING_LAG = Duration.ofMinutes(2);

    private final SessionManagementService sessions;
    private final Duration idleLimit;

    /**
     * @param sessionTimeout the idle limit of the application's HTTP sessions ({@code server.servlet.session.timeout});
     *                       null for the container's default, zero or less for sessions that never time out
     */
    public ActiveSessionCleanupScheduler(SessionManagementService sessions, @Nullable Duration sessionTimeout) {
        this.sessions = sessions;
        Duration timeout = sessionTimeout != null ? sessionTimeout : DEFAULT_IDLE_LIMIT;
        this.idleLimit = timeout.isZero() || timeout.isNegative() ? Duration.ZERO : timeout.plus(TRACKING_LAG);
    }

    /** How long a session no request reached stays counted active; zero when sessions never time out. */
    Duration idleLimit() {
        return idleLimit;
    }

    @Scheduled(scheduler = "contexaTaskScheduler", fixedDelay = 300_000, initialDelay = 60_000)
    @SchedulerLock(name = "activeSessionCleanup", lockAtMostFor = "PT10M", lockAtLeastFor = "PT1M")
    public void cleanup() {
        try {
            int idle = sessions.endIdleSessions(idleLimit);
            sessions.cleanupExpiredSessions();
            if (idle > 0) {
                log.info("[SessionCleanup] {} sessions no request reached for {} are no longer active", idle,
                        idleLimit);
            }
        } catch (RuntimeException e) {
            log.error("[SessionCleanup] The tracked sessions could not be cleaned up", e);
        }
    }
}
