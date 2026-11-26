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
package io.contexa.contexacommon.bridge.sync;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.BridgeUserProfile;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The copy of an application's user is one per person (and organization), whichever way the bridge read the person: the
 * security context, an explicit handoff, the session. With the way in its key, one person was a copy per way, and the
 * step-up offers no factor to a person with more than one copy. The repository here answers as the table would.
 */
class OneCopyAcrossCollectionPathsTest {

    private final UserRepository users = mock(UserRepository.class);
    private final BridgeUserProfileRepository profiles = mock(BridgeUserProfileRepository.class);
    private final List<Users> rows = new ArrayList<>();
    private final Map<Long, BridgeUserProfile> profileRows = new HashMap<>();
    private long nextId = 1;

    @BeforeEach
    void table() {
        when(users.findByBridgeSubjectKey(anyString())).thenAnswer(call -> rows.stream()
                .filter(row -> call.getArgument(0, String.class).equals(row.getBridgeSubjectKey())).findFirst());
        when(users.findByExternalSubjectIdAndBridgeManagedTrue(anyString())).thenAnswer(call -> rows.stream()
                .filter(row -> row.isBridgeManaged() && call.getArgument(0, String.class).equals(row.getExternalSubjectId()))
                .toList());
        when(users.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationId(anyString(), anyString(), anyString()))
                .thenAnswer(call -> rows.stream()
                        .filter(row -> call.getArgument(0, String.class).equals(row.getExternalSubjectId())
                                && call.getArgument(1, String.class).equals(row.getAuthenticationSource())
                                && call.getArgument(2, String.class).equals(row.getOrganizationId()))
                        .findFirst());
        when(users.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationIdIsNull(anyString(), anyString()))
                .thenAnswer(call -> rows.stream()
                        .filter(row -> call.getArgument(0, String.class).equals(row.getExternalSubjectId())
                                && call.getArgument(1, String.class).equals(row.getAuthenticationSource())
                                && row.getOrganizationId() == null)
                        .findFirst());
        when(users.findFirstByEmailIgnoreCase(anyString())).thenAnswer(call -> rows.stream()
                .filter(row -> call.getArgument(0, String.class).equalsIgnoreCase(row.getEmail())).findFirst());
        when(users.save(any(Users.class))).thenAnswer(call -> {
            Users row = call.getArgument(0);
            if (row.getId() == null) {
                row.setId(nextId++);
                rows.add(row);
            }
            return row;
        });
        when(profiles.findById(anyLong())).thenAnswer(call -> Optional.ofNullable(profileRows.get(call.getArgument(0, Long.class))));
        when(profiles.save(any(BridgeUserProfile.class))).thenAnswer(call -> {
            BridgeUserProfile profile = call.getArgument(0);
            profileRows.put(profile.getUser().getId(), profile);
            return profile;
        });
    }

    @Test
    @DisplayName("같은 사람은 보안 문맥으로 읽든 직접 전달로 읽든 사본이 하나다")
    void onePersonIsOneCopyWhicheverWayTheBridgeReadThem() {
        DefaultBridgeUserMirrorSyncService sync = sync();

        BridgeUserMirrorSyncResult fromTheContext = sync.sync(stamp("alice", "SECURITY_CONTEXT", null), null, request());
        BridgeUserMirrorSyncResult fromAHandoff = sync.sync(stamp("alice", "EXPLICIT_HANDOFF", null), null, request());
        BridgeUserMirrorSyncResult fromTheSession = sync.sync(stamp("alice", "SESSION", null), null, request());

        assertThat(rows).hasSize(1);
        assertThat(fromAHandoff.internalUserId()).isEqualTo(fromTheContext.internalUserId());
        assertThat(fromTheSession.internalUserId()).isEqualTo(fromTheContext.internalUserId());
        assertThat(fromAHandoff.bridgeSubjectKey()).isEqualTo(fromTheContext.bridgeSubjectKey());
        assertThat(users.findByExternalSubjectIdAndBridgeManagedTrue("alice")).hasSize(1);
    }

    @Test
    @DisplayName("옛 키로 저장된 사본은 다른 길로 읽힌 다음 요청에서도 그 사본으로 찾아지고 새 행을 만들지 않는다")
    void aCopyKeptUnderTheOldKeyIsTheCopyWhicheverWayReadsThePersonNext() {
        Users kept = oldCopy("alice", "SECURITY_CONTEXT", null);
        DefaultBridgeUserMirrorSyncService sync = sync();

        BridgeUserMirrorSyncResult result = sync.sync(stamp("alice", "EXPLICIT_HANDOFF", null), null, request());

        assertThat(rows).hasSize(1);
        assertThat(result.internalUserId()).isEqualTo(kept.getId());
        assertThat(result.internalUsername()).as("the name others refer to the copy by stays").isEqualTo(oldKey("SECURITY_CONTEXT", null, "alice"));
        assertThat(kept.getBridgeSubjectKey()).isEqualTo(result.bridgeSubjectKey());

        BridgeUserMirrorSyncResult next = sync.sync(stamp("alice", "SECURITY_CONTEXT", null), null, request());
        assertThat(next.internalUserId()).isEqualTo(kept.getId());
        assertThat(rows).hasSize(1);
    }

    @Test
    @DisplayName("이미 길마다 갈라진 사본이 있으면 가장 먼저 만든 사본을 쓰고 세 번째 사본을 만들지 않는다")
    void copiesAlreadySplitLeaveTheOldestStandingAndNoThirdIsMade() {
        Users first = oldCopy("alice", "SECURITY_CONTEXT", "org-a");
        Users second = oldCopy("alice", "EXPLICIT_HANDOFF", "org-a");
        DefaultBridgeUserMirrorSyncService sync = sync();

        BridgeUserMirrorSyncResult fromTheSession = sync.sync(stamp("alice", "SESSION", "org-a"), null, request());
        BridgeUserMirrorSyncResult fromAHandoff = sync.sync(stamp("alice", "EXPLICIT_HANDOFF", "org-a"), null, request());

        assertThat(rows).hasSize(2);
        assertThat(fromTheSession.internalUserId()).isEqualTo(first.getId());
        assertThat(fromAHandoff.internalUserId()).as("the copy found by the key stays the one").isEqualTo(first.getId());
        assertThat(second.getBridgeSubjectKey()).isEqualTo(oldKey("EXPLICIT_HANDOFF", "org-a", "alice"));
    }

    @Test
    @DisplayName("조직이 다르면 지금처럼 다른 사본이다")
    void anotherOrganizationIsStillAnotherCopy() {
        DefaultBridgeUserMirrorSyncService sync = sync();

        sync.sync(stamp("alice", "SECURITY_CONTEXT", "org-a"), null, request());
        sync.sync(stamp("alice", "SECURITY_CONTEXT", "org-b"), null, request());

        assertThat(rows).hasSize(2);
    }

    @Test
    @DisplayName("옛 키로 지어낸 주소를 가진 사본에도 애플리케이션이 알려 주는 주소를 묻는다")
    void theApplicationIsAskedForTheAddressOfACopyWithTheMadeUpAddressOfItsOldKey() {
        Users kept = oldCopy("alice", "SECURITY_CONTEXT", null);
        DefaultBridgeUserMirrorSyncService sync = sync();
        sync.setEmailProvider(principal -> "alice".equals(principal) ? "Alice@Corp.Example" : null);

        sync.sync(stamp("alice", "EXPLICIT_HANDOFF", null), null, request());

        assertThat(rows).hasSize(1);
        assertThat(kept.getEmail()).isEqualTo("alice@corp.example");
    }

    private DefaultBridgeUserMirrorSyncService sync() {
        return new DefaultBridgeUserMirrorSyncService(users, profiles, new BridgeProperties(), new ObjectMapper(), null);
    }

    /** A copy the synchronisation made before, under the key that named the way the person was read. */
    private Users oldCopy(String subject, String source, String organization) {
        String key = oldKey(source, organization, subject);
        Users row = Users.builder()
                .username(key)
                .password("{bcrypt}x")
                .name(subject)
                .email(key + "@shadow.contexa.local")
                .enabled(true)
                .bridgeManaged(true)
                .externalAuthOnly(true)
                .externalSubjectId(subject)
                .authenticationSource(source)
                .organizationId(organization)
                .bridgeSubjectKey(key)
                .lastBridgedAt(LocalDateTime.now().minusDays(1))
                .build();
        row.setId(nextId++);
        rows.add(row);
        return row;
    }

    private static String oldKey(String source, String organization, String subject) {
        return "brg_" + sha256(source + "|" + (organization != null ? organization : "GLOBAL") + "|" + subject);
    }

    private static AuthenticationStamp stamp(String subject, String source, String organization) {
        Map<String, Object> attributes = organization != null ? Map.of("organizationId", organization) : Map.of();
        return new AuthenticationStamp(subject, subject, "USER", true, "FORM", source, null, null,
                Instant.parse("2026-11-25T01:00:00Z"), "s-1", List.of("ROLE_USER"), attributes);
    }

    private static RequestContextSnapshot request() {
        return new RequestContextSnapshot("/orders", "GET", "10.0.0.10", "JUnit", "s-1", "r-1", "/orders", null, false,
                Instant.parse("2026-11-25T01:00:02Z"));
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
