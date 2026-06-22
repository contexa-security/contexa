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
package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.ActiveSession;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface ActiveSessionRepository extends JpaRepository<ActiveSession, String> {

    List<ActiveSession> findByExpiredFalseOrderByLastAccessedAtDesc();

    List<ActiveSession> findByUserIdAndExpiredFalse(String userId);

    long countByExpiredFalse();

    long countByUserId(String userId);

    @Modifying
    @Query("UPDATE ActiveSession s SET s.expired = true WHERE s.sessionId = :sessionId")
    void expireSession(@Param("sessionId") String sessionId);

    @Modifying
    @Query("UPDATE ActiveSession s SET s.expired = true WHERE s.userId = :userId")
    void expireAllSessionsForUser(@Param("userId") String userId);

    @Modifying
    @Query("DELETE FROM ActiveSession s WHERE s.expired = true AND s.lastAccessedAt < :before")
    void deleteExpiredBefore(@Param("before") LocalDateTime before);

    Page<ActiveSession> findByExpiredFalse(Pageable pageable);

    @Query("SELECT s FROM ActiveSession s WHERE s.expired = false AND (lower(s.username) LIKE :keyword OR lower(s.clientIp) LIKE :keyword) ORDER BY s.lastAccessedAt DESC")
    Page<ActiveSession> searchActiveSessions(@Param("keyword") String keyword, Pageable pageable);

    @Modifying
    @Query(value = """
            INSERT INTO active_sessions (
                session_id,
                user_id,
                username,
                client_ip,
                user_agent,
                created_at,
                last_accessed_at,
                expired
            ) VALUES (
                :sessionId,
                :userId,
                :username,
                :clientIp,
                :userAgent,
                :now,
                :now,
                false
            )
            ON CONFLICT (session_id) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                username = EXCLUDED.username,
                client_ip = EXCLUDED.client_ip,
                user_agent = EXCLUDED.user_agent,
                expired = false,
                last_accessed_at = CASE
                    WHEN active_sessions.expired = true
                      OR active_sessions.last_accessed_at IS NULL
                      OR active_sessions.last_accessed_at < :updateThreshold
                    THEN EXCLUDED.last_accessed_at
                    ELSE active_sessions.last_accessed_at
                END
            """, nativeQuery = true)
    void upsertSession(
            @Param("sessionId") String sessionId,
            @Param("userId") String userId,
            @Param("username") String username,
            @Param("clientIp") String clientIp,
            @Param("userAgent") String userAgent,
            @Param("now") LocalDateTime now,
            @Param("updateThreshold") LocalDateTime updateThreshold);
}
