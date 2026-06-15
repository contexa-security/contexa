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

import io.contexa.contexaiam.domain.entity.ActiveSession;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("SessionManagementService")
class SessionManagementServiceTest {

    @Mock
    private ActiveSessionRepository activeSessionRepository;

    @InjectMocks
    private SessionManagementService service;

    @Nested
    @DisplayName("getActiveSessions")
    class GetActiveSessions {

        @Test
        @DisplayName("should return paged active sessions")
        void success() {
            Pageable pageable = PageRequest.of(0, 10);
            ActiveSession session = ActiveSession.builder().sessionId("sess-1").build();
            Page<ActiveSession> page = new PageImpl<>(List.of(session));

            when(activeSessionRepository.findByExpiredFalse(pageable)).thenReturn(page);

            Page<ActiveSession> result = service.getActiveSessions(pageable);

            assertThat(result.getContent()).containsExactly(session);
        }
    }

    @Nested
    @DisplayName("getSessionsByUser")
    class GetSessionsByUser {

        @Test
        @DisplayName("should return active sessions for a user")
        void success() {
            ActiveSession session = ActiveSession.builder().sessionId("sess-1").userId("user-1").build();
            when(activeSessionRepository.findByUserIdAndExpiredFalse("user-1")).thenReturn(List.of(session));

            List<ActiveSession> result = service.getSessionsByUser("user-1");

            assertThat(result).containsExactly(session);
        }
    }

    @Nested
    @DisplayName("getActiveSessionCount")
    class GetActiveSessionCount {

        @Test
        @DisplayName("should return count of active sessions")
        void success() {
            when(activeSessionRepository.countByExpiredFalse()).thenReturn(5L);

            long count = service.getActiveSessionCount();

            assertThat(count).isEqualTo(5L);
        }
    }

    @Nested
    @DisplayName("invalidateSession")
    class InvalidateSession {

        @Test
        @DisplayName("should call expireSession on repository")
        void success() {
            service.invalidateSession("sess-1");

            verify(activeSessionRepository).expireSession("sess-1");
        }
    }

    @Nested
    @DisplayName("invalidateAllSessionsForUser")
    class InvalidateAllSessionsForUser {

        @Test
        @DisplayName("should call expireAllSessionsForUser on repository")
        void success() {
            service.invalidateAllSessionsForUser("user-1");

            verify(activeSessionRepository).expireAllSessionsForUser("user-1");
        }
    }

    @Nested
    @DisplayName("trackSession")
    class TrackSession {

        @Test
        @DisplayName("should create new session when session id is not present")
        void createNew() {
            when(activeSessionRepository.findById("new-sess")).thenReturn(Optional.empty());

            service.trackSession("new-sess", "user-1", "user1", "127.0.0.1", "Chrome");

            verify(activeSessionRepository).save(argThat(session ->
                    session.getSessionId().equals("new-sess") &&
                    session.getUserId().equals("user-1") &&
                    session.getUsername().equals("user1") &&
                    session.getClientIp().equals("127.0.0.1") &&
                    session.getUserAgent().equals("Chrome") &&
                    !session.isExpired()
            ));
        }

        @Test
        @DisplayName("should truncate userAgent when it exceeds 512 characters")
        void userAgentTruncation() {
            String longAgent = "A".repeat(600);
            when(activeSessionRepository.findById("new-sess")).thenReturn(Optional.empty());

            service.trackSession("new-sess", "user-1", "user1", "127.0.0.1", longAgent);

            verify(activeSessionRepository).save(argThat(session ->
                    session.getUserAgent().length() == 512 &&
                    session.getUserAgent().equals("A".repeat(512))
            ));
        }

        @Test
        @DisplayName("should update lastAccessedAt when existing session exceeds threshold")
        void updateExisting() {
            LocalDateTime oldTime = LocalDateTime.now().minusSeconds(70);
            ActiveSession existing = ActiveSession.builder()
                    .sessionId("old-sess")
                    .expired(false)
                    .lastAccessedAt(oldTime)
                    .build();

            when(activeSessionRepository.findById("old-sess")).thenReturn(Optional.of(existing));

            service.trackSession("old-sess", "user-1", "user1", "127.0.0.1", "Chrome");

            verify(activeSessionRepository).save(existing);
            assertThat(existing.getLastAccessedAt()).isAfter(oldTime);
        }

        @Test
        @DisplayName("should not update lastAccessedAt when existing session is within threshold")
        void doNotUpdateWithinThreshold() {
            LocalDateTime recentTime = LocalDateTime.now().minusSeconds(10);
            ActiveSession existing = ActiveSession.builder()
                    .sessionId("old-sess")
                    .expired(false)
                    .lastAccessedAt(recentTime)
                    .build();

            when(activeSessionRepository.findById("old-sess")).thenReturn(Optional.of(existing));

            service.trackSession("old-sess", "user-1", "user1", "127.0.0.1", "Chrome");

            verify(activeSessionRepository, never()).save(any(ActiveSession.class));
        }
    }

    @Nested
    @DisplayName("updateLastAccessed")
    class UpdateLastAccessed {

        @Test
        @DisplayName("should update lastAccessedAt for unexpired session")
        void success() {
            LocalDateTime oldTime = LocalDateTime.now().minusHours(1);
            ActiveSession existing = ActiveSession.builder()
                    .sessionId("sess-1")
                    .expired(false)
                    .lastAccessedAt(oldTime)
                    .build();

            when(activeSessionRepository.findById("sess-1")).thenReturn(Optional.of(existing));

            service.updateLastAccessed("sess-1");

            verify(activeSessionRepository).save(existing);
            assertThat(existing.getLastAccessedAt()).isAfter(oldTime);
        }

        @Test
        @DisplayName("should not update lastAccessedAt for expired session")
        void expiredSession() {
            LocalDateTime oldTime = LocalDateTime.now().minusHours(1);
            ActiveSession existing = ActiveSession.builder()
                    .sessionId("sess-1")
                    .expired(true)
                    .lastAccessedAt(oldTime)
                    .build();

            when(activeSessionRepository.findById("sess-1")).thenReturn(Optional.of(existing));

            service.updateLastAccessed("sess-1");

            verify(activeSessionRepository, never()).save(any(ActiveSession.class));
        }
    }

    @Nested
    @DisplayName("markExpired")
    class MarkExpired {

        @Test
        @DisplayName("should call expireSession on repository")
        void success() {
            service.markExpired("sess-1");

            verify(activeSessionRepository).expireSession("sess-1");
        }
    }

    @Nested
    @DisplayName("cleanupExpiredSessions")
    class CleanupExpiredSessions {

        @Test
        @DisplayName("should call deleteExpiredBefore with 7 days threshold")
        void success() {
            service.cleanupExpiredSessions();

            verify(activeSessionRepository).deleteExpiredBefore(argThat(time ->
                    time.isBefore(LocalDateTime.now().minusDays(6).minusHours(23)) &&
                    time.isAfter(LocalDateTime.now().minusDays(7).minusMinutes(5))
            ));
        }
    }

    @Nested
    @DisplayName("getAllActiveSessions")
    class GetAllActiveSessions {

        @Test
        @DisplayName("should return all active sessions sorted by last accessed descending")
        void success() {
            ActiveSession s1 = ActiveSession.builder().sessionId("s1").build();
            when(activeSessionRepository.findByExpiredFalseOrderByLastAccessedAtDesc()).thenReturn(List.of(s1));

            List<ActiveSession> result = service.getAllActiveSessions();

            assertThat(result).containsExactly(s1);
        }
    }
}
