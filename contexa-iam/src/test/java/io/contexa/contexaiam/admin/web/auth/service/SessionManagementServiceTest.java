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

import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
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
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
            tracked("sess-1", "user-1");

            assertThat(service.invalidateSession("sess-1")).isFalse();

            verify(activeSessionRepository).expireSession(ref("sess-1"));
        }

        @Test
        @DisplayName("ends every sign-in of the session's person through the forced logout")
        void endsTheSignInsOfItsPerson() {
            IForceLogoutService logout = mock(IForceLogoutService.class);
            SessionManagementService ending = new SessionManagementService(activeSessionRepository, null, () -> logout);
            tracked("sess-1", "user-1");

            assertThat(ending.invalidateSession("sess-1")).isTrue();

            verify(activeSessionRepository).expireSession(ref("sess-1"));
            verify(logout).forceLogoutByUserId(eq("user-1"), any());
        }

        @Test
        @DisplayName("refuses a session no one tracks, and ends no sign-in for it")
        void refusesAnUnknownSession() {
            IForceLogoutService logout = mock(IForceLogoutService.class);
            SessionManagementService ending = new SessionManagementService(activeSessionRepository, null, () -> logout);
            when(activeSessionRepository.findById(ref("gone"))).thenReturn(Optional.empty());

            assertThatThrownBy(() -> ending.invalidateSession("gone")).isInstanceOf(NoSuchElementException.class);

            verify(activeSessionRepository, never()).expireSession(any());
            verifyNoInteractions(logout);
        }
    }

    @Nested
    @DisplayName("invalidateAllSessionsForUser")
    class InvalidateAllSessionsForUser {

        @Test
        @DisplayName("should call expireAllSessionsForUser on repository")
        void success() {
            assertThat(service.invalidateAllSessionsForUser("user-1")).isFalse();

            verify(activeSessionRepository).expireAllSessionsForUser("user-1");
        }

        @Test
        @DisplayName("ends every sign-in of the person, also those the console never tracked")
        void endsTheSignInsOfThePerson() {
            IForceLogoutService logout = mock(IForceLogoutService.class);
            SessionManagementService ending = new SessionManagementService(activeSessionRepository, null, () -> logout);

            assertThat(ending.invalidateAllSessionsForUser("user-1")).isTrue();

            verify(activeSessionRepository).expireAllSessionsForUser("user-1");
            verify(logout).forceLogoutByUserId(eq("user-1"), any());
        }
    }

    @Nested
    @DisplayName("trackSession")
    class TrackSession {

        @Test
        @DisplayName("should upsert a new session without a read-before-write")
        void createNew() {
            service.trackSession("new-sess", "user-1", "user1", "127.0.0.1", "Chrome");

            verify(activeSessionRepository).upsertSession(
                    eq(ref("new-sess")), eq("user-1"), eq("user1"), eq("127.0.0.1"), eq("Chrome"),
                    any(LocalDateTime.class), any(LocalDateTime.class));
            verify(activeSessionRepository, never()).findById(ref("new-sess"));
        }

        @Test
        @DisplayName("should truncate userAgent when it exceeds 512 characters")
        void userAgentTruncation() {
            String longAgent = "A".repeat(600);

            service.trackSession("new-sess", "user-1", "user1", "127.0.0.1", longAgent);

            verify(activeSessionRepository).upsertSession(
                    eq(ref("new-sess")), eq("user-1"), eq("user1"), eq("127.0.0.1"), eq("A".repeat(512)),
                    any(LocalDateTime.class), any(LocalDateTime.class));
        }

        @Test
        @DisplayName("should pass a sixty-second update threshold to the atomic upsert")
        void updateThreshold() {
            service.trackSession("old-sess", "user-1", "user1", "127.0.0.1", "Chrome");

            verify(activeSessionRepository).upsertSession(
                    eq(ref("old-sess")), eq("user-1"), eq("user1"), eq("127.0.0.1"), eq("Chrome"),
                    any(LocalDateTime.class),
                    argThat(threshold -> threshold.isBefore(LocalDateTime.now().minusSeconds(59))
                            && threshold.isAfter(LocalDateTime.now().minusSeconds(65))));
        }

        @Test
        @DisplayName("should delegate recency handling to the database upsert")
        void recencyIsHandledAtomically() {
            service.trackSession("old-sess", "user-1", "user1", "127.0.0.1", "Chrome");

            verify(activeSessionRepository).upsertSession(
                    eq(ref("old-sess")), eq("user-1"), eq("user1"), eq("127.0.0.1"), eq("Chrome"),
                    any(LocalDateTime.class), any(LocalDateTime.class));
            verify(activeSessionRepository, never()).findById(ref("old-sess"));
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
                    .sessionId(ref("sess-1"))
                    .expired(false)
                    .lastAccessedAt(oldTime)
                    .build();

            when(activeSessionRepository.findById(ref("sess-1"))).thenReturn(Optional.of(existing));

            service.updateLastAccessed("sess-1");

            verify(activeSessionRepository).save(existing);
            assertThat(existing.getLastAccessedAt()).isAfter(oldTime);
        }

        @Test
        @DisplayName("should not update lastAccessedAt for expired session")
        void expiredSession() {
            LocalDateTime oldTime = LocalDateTime.now().minusHours(1);
            ActiveSession existing = ActiveSession.builder()
                    .sessionId(ref("sess-1"))
                    .expired(true)
                    .lastAccessedAt(oldTime)
                    .build();

            when(activeSessionRepository.findById(ref("sess-1"))).thenReturn(Optional.of(existing));

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

            verify(activeSessionRepository).expireSession(ref("sess-1"));
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

    @Nested
    @DisplayName("the session's identifier")
    class SessionIdentifier {

        @Test
        @DisplayName("is kept as its reference, never as the value a cookie carries")
        void keptAsItsReference() {
            service.trackSession("RAW-COOKIE-VALUE", "user-1", "user1", "127.0.0.1", "Chrome");

            verify(activeSessionRepository).upsertSession(eq(ref("RAW-COOKIE-VALUE")), eq("user-1"), eq("user1"),
                    eq("127.0.0.1"), eq("Chrome"), any(LocalDateTime.class), any(LocalDateTime.class));
            verify(activeSessionRepository, never()).upsertSession(eq("RAW-COOKIE-VALUE"), any(), any(), any(), any(),
                    any(), any());
            assertThat(ref("RAW-COOKIE-VALUE")).startsWith("sid-").doesNotContain("RAW-COOKIE-VALUE");
        }

        @Test
        @DisplayName("is invalidated by its reference, and by the raw value too for a caller that still has one")
        void invalidatedByItsReference() {
            tracked("RAW-COOKIE-VALUE", "user-1");
            service.invalidateSession(ref("RAW-COOKIE-VALUE"));
            service.invalidateSession("RAW-COOKIE-VALUE");

            verify(activeSessionRepository, times(2)).expireSession(ref("RAW-COOKIE-VALUE"));
            verify(activeSessionRepository, never()).expireSession("RAW-COOKIE-VALUE");
        }
    }

    private void tracked(String sessionId, String userId) {
        when(activeSessionRepository.findById(ref(sessionId))).thenReturn(Optional.of(
                ActiveSession.builder().sessionId(ref(sessionId)).userId(userId).username(userId).build()));
    }

    private static String ref(String sessionId) {
        return RequestFactRedaction.sessionReference(sessionId);
    }
}
