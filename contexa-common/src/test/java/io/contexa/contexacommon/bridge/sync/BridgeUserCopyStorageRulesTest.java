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
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserCopyFacts;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The rules of the copy Contexa keeps of an application's user (bridge v2, step B5-1): what is stored, when it is written,
 * and under which key.
 */
@DisplayName("레거시 사용자 사본의 저장 규칙")
class BridgeUserCopyStorageRulesTest {

    private static final UnaryOperator<String> DECISION_KEY = id -> Normalizer.normalize(id, Normalizer.Form.NFKC)
            .strip().toUpperCase(Locale.ROOT).toLowerCase(Locale.ROOT);

    private final UserRepository users = mock(UserRepository.class);
    private final BridgeUserProfileRepository profiles = mock(BridgeUserProfileRepository.class);
    private final AtomicReference<Users> storedUser = new AtomicReference<>();
    private final AtomicReference<BridgeUserProfile> storedProfile = new AtomicReference<>();
    private final AtomicInteger userWrites = new AtomicInteger();
    private final AtomicInteger profileWrites = new AtomicInteger();

    private DefaultBridgeUserMirrorSyncService storing() {
        when(users.findByBridgeSubjectKey(anyString())).thenAnswer(invocation -> Optional.ofNullable(storedUser.get())
                .filter(user -> invocation.getArgument(0).equals(user.getBridgeSubjectKey())));
        when(users.save(any(Users.class))).thenAnswer(invocation -> {
            Users user = invocation.getArgument(0);
            if (user.getId() == null) {
                user.setId(100L);
            }
            storedUser.set(user);
            userWrites.incrementAndGet();
            return user;
        });
        when(profiles.findById(anyLong())).thenAnswer(invocation -> Optional.ofNullable(storedProfile.get()));
        when(profiles.save(any(BridgeUserProfile.class))).thenAnswer(invocation -> {
            BridgeUserProfile profile = invocation.getArgument(0);
            storedProfile.set(profile);
            profileWrites.incrementAndGet();
            return profile;
        });
        return new DefaultBridgeUserMirrorSyncService(users, profiles, new BridgeProperties(), new ObjectMapper(), null);
    }

    @Test
    @DisplayName("예전에 만든 가짜 메일은 레거시가 메일을 주지 않으면 비운다")
    void aMadeUpAddressOfBeforeIsCleared() {
        DefaultBridgeUserMirrorSyncService service = storing();
        service.sync(stamp("USR001", "Alice", Map.of()), authorization(), request("10.0.0.10"));
        storedUser.get().setEmail(storedUser.get().getBridgeSubjectKey() + "@shadow.contexa.local");

        service.sync(stamp("USR001", "Alice", Map.of()), authorization(), request("10.0.0.10"));

        assertThat(storedUser.get().getEmail()).isNull();
    }

    @Test
    @DisplayName("관리자가 끈 사본은 동기화로 다시 켜지지 않는다")
    void aCopyAnAdministratorTurnedOffStaysOff() {
        DefaultBridgeUserMirrorSyncService service = storing();
        service.sync(stamp("USR001", "Alice", Map.of()), authorization(), request("10.0.0.10"));
        storedUser.get().setEnabled(false);

        service.sync(stamp("USR001", "Alice Kim", Map.of()), authorization(), request("10.0.0.10"));

        assertThat(storedUser.get().getName()).as("the change was written").isEqualTo("Alice Kim");
        assertThat(storedUser.get().isEnabled()).isFalse();
    }

    @Test
    @DisplayName("요청 IP만 바뀌면 사본에 쓰지 않는다")
    void anotherAddressOfTheRequestWritesNothing() {
        DefaultBridgeUserMirrorSyncService service = storing();
        service.sync(stamp("USR001", "Alice", Map.of()), authorization(), request("10.0.0.10"));

        service.sync(stamp("USR001", "Alice", Map.of()), authorization(), request("10.0.0.99"));

        assertThat(userWrites.get()).isEqualTo(1);
        assertThat(profileWrites.get()).isEqualTo(1);
    }

    @Test
    @DisplayName("사본에 저장하지 않는 토큰 클레임만 바뀌면 사본에 쓰지 않는다")
    void aRefreshedTokenWritesNothing() {
        DefaultBridgeUserMirrorSyncService service = storing();
        service.sync(stamp("USR001", "Alice", Map.of("jti", "token-1", "exp", "1000")), authorization(),
                request("10.0.0.10"));

        service.sync(stamp("USR001", "Alice", Map.of("jti", "token-2", "exp", "2000")), authorization(),
                request("10.0.0.10"));

        assertThat(userWrites.get()).isEqualTo(1);
        assertThat(profileWrites.get()).isEqualTo(1);
    }

    @Test
    @DisplayName("저장하는 값인 표시 이름이 바뀌면 사본에 쓴다")
    void aChangedDisplayNameIsWritten() {
        DefaultBridgeUserMirrorSyncService service = storing();
        service.sync(stamp("USR001", "Alice", Map.of()), authorization(), request("10.0.0.10"));

        service.sync(stamp("USR001", "Alice Kim", Map.of()), authorization(), request("10.0.0.10"));

        assertThat(userWrites.get()).isEqualTo(2);
        assertThat(storedUser.get().getName()).isEqualTo("Alice Kim");
    }

    @Test
    @DisplayName("마지막 로그인 IP는 로그인 동기화에서만 쓴다")
    void onlyASignInWritesTheLastSignIn() {
        DefaultBridgeUserMirrorSyncService service = storing();
        service.sync(stamp("USR001", "Alice", Map.of()), authorization(), request("10.0.0.10"), true);

        service.sync(stamp("USR001", "Alice", Map.of()), authorization(), request("10.0.0.20"), false);
        String afterARequest = storedUser.get().getLastLoginIp();
        service.sync(stamp("USR001", "Alice", Map.of()), authorization(), request("10.0.0.30"), true);

        assertThat(afterARequest).isEqualTo("10.0.0.10");
        assertThat(storedUser.get().getLastLoginIp()).isEqualTo("10.0.0.30");
        assertThat(userWrites.get()).isEqualTo(2);
    }

    @Test
    @DisplayName("세션 ID와 속성 전체는 저장하지 않고 예전 값은 비운다")
    void theSessionAndTheAttributesAreNotKept() {
        DefaultBridgeUserMirrorSyncService service = storing();
        service.sync(stamp("USR001", "Alice", Map.of("tenantId", "tenant-a")), authorization(), request("10.0.0.10"));
        assertThat(storedProfile.get().getSessionId()).isNull();
        assertThat(storedProfile.get().getLastAttributesJson()).isNull();
        storedProfile.get().setSessionId("session-of-before");
        storedProfile.get().setLastAttributesJson("{\"tenantId\":\"tenant-a\"}");

        service.sync(stamp("USR001", "Alice", Map.of("tenantId", "tenant-a")), authorization(), request("10.0.0.10"));

        assertThat(storedProfile.get().getSessionId()).isNull();
        assertThat(storedProfile.get().getLastAttributesJson()).isNull();
    }

    @Test
    @DisplayName("권한은 레거시가 준 것만 저장하고 인가 해석 결과는 저장하지 않는다")
    void onlyTheApplicationsAuthoritiesAreKept() {
        DefaultBridgeUserMirrorSyncService service = storing();

        service.sync(stamp("USR001", "Alice", Map.of()), authorization(), request("10.0.0.10"));

        assertThat(storedProfile.get().getLastAuthoritiesJson()).contains("ROLE_ADMIN", "REPORT_EXPORT")
                .doesNotContain("INTERPRETED_AUTHORITY");
    }

    @Test
    @DisplayName("사본은 판정 키(접은 아이디)로 저장된다")
    void theCopyIsKeyedByTheDecisionKey() throws Exception {
        DefaultBridgeUserMirrorSyncService service = storing();
        service.setUserKey(DECISION_KEY);

        service.sync(stamp("Kim01", "Kim", Map.of()), authorization(), request("10.0.0.10"));

        assertThat(storedUser.get().getExternalSubjectId()).isEqualTo("kim01");
        assertThat(storedUser.get().getBridgeSubjectKey()).isEqualTo("brg_" + sha256("SUBJECT|GLOBAL|kim01"));
    }

    @Test
    @DisplayName("원래 아이디로 만든 옛 사본은 찾아서 판정 키로 옮기고 새 행을 만들지 않는다")
    void aCopyKeptUnderTheOldKeyMovesToTheDecisionKey() throws Exception {
        DefaultBridgeUserMirrorSyncService service = storing();
        service.setUserKey(DECISION_KEY);
        String oldKey = "brg_" + sha256("SUBJECT|GLOBAL|Kim01");
        Users before = Users.builder().id(55L).username(oldKey).password("x").name("Kim").bridgeManaged(true)
                .externalAuthOnly(true).externalSubjectId("Kim01").bridgeSubjectKey(oldKey).build();
        storedUser.set(before);

        service.sync(stamp("Kim01", "Kim", Map.of()), authorization(), request("10.0.0.10"));

        assertThat(storedUser.get().getId()).isEqualTo(55L);
        assertThat(storedUser.get().getBridgeSubjectKey()).isEqualTo("brg_" + sha256("SUBJECT|GLOBAL|kim01"));
        assertThat(storedUser.get().getExternalSubjectId()).isEqualTo("kim01");
        assertThat(userWrites.get()).isEqualTo(1);
    }

    @Test
    @DisplayName("다른 사본과 같은 메일도 본인 확인 뒤 사본 메일로 확정한다")
    void anAddressAnotherCopyUsesCanBeConfirmed() {
        DefaultBridgeUserMirrorSyncService service = storing();
        Users copy = Users.builder().id(100L).username("brg_x").password("x").name("Alice").bridgeManaged(true)
                .email("old@corp.example").build();
        BridgeUserProfile profile = BridgeUserProfile.builder().userId(100L).user(copy).pendingEmail("team@corp.example")
                .build();
        storedUser.set(copy);
        storedProfile.set(profile);
        when(users.findById(100L)).thenReturn(Optional.of(copy));
        when(users.findFirstByEmailIgnoreCaseAndBridgeManagedFalse("team@corp.example")).thenReturn(Optional.empty());

        boolean confirmed = service.confirmPendingEmail(100L, "team@corp.example");

        assertThat(confirmed).isTrue();
        assertThat(copy.getEmail()).isEqualTo("team@corp.example");
    }

    @Test
    @DisplayName("Contexa 계정이 쓰는 메일은 사본 메일로 확정하지 않는다")
    void anAddressOfAContexaAccountIsNotTaken() {
        DefaultBridgeUserMirrorSyncService service = storing();
        Users copy = Users.builder().id(100L).username("brg_x").password("x").name("Alice").bridgeManaged(true)
                .email("old@corp.example").build();
        BridgeUserProfile profile = BridgeUserProfile.builder().userId(100L).user(copy).pendingEmail("admin@corp.example")
                .build();
        storedUser.set(copy);
        storedProfile.set(profile);
        when(users.findById(100L)).thenReturn(Optional.of(copy));
        Users account = Users.builder().id(1L).username("admin").password("x").name("Admin").build();
        when(users.findFirstByEmailIgnoreCaseAndBridgeManagedFalse(eq("admin@corp.example")))
                .thenReturn(Optional.of(account));

        boolean confirmed = service.confirmPendingEmail(100L, "admin@corp.example");

        assertThat(confirmed).isFalse();
        assertThat(copy.getEmail()).isEqualTo("old@corp.example");
    }

    @Test
    @DisplayName("요청 경로의 기억 키에는 IP와 저장하지 않는 클레임이 들어가지 않는다")
    void theFactsOfACopyLeaveOutTheRequestAndTheToken() {
        List<Object> first = BridgeUserCopyFacts.of(stamp("USR001", "Alice", Map.of("jti", "token-1", "exp", "1")));
        List<Object> refreshed = BridgeUserCopyFacts.of(stamp("USR001", "Alice", Map.of("jti", "token-2", "exp", "2")));
        List<Object> renamed = BridgeUserCopyFacts.of(stamp("USR001", "Alice Kim", Map.of("jti", "token-2")));

        assertThat(refreshed).isEqualTo(first);
        assertThat(renamed).isNotEqualTo(first);
    }

    private static AuthenticationStamp stamp(String principal, String displayName, Map<String, Object> extra) {
        Map<String, Object> attributes = new HashMap<>(Map.of("department", "finance"));
        attributes.putAll(extra);
        return new AuthenticationStamp(principal, displayName, "USER", true, "SESSION", "SESSION", "HIGH", true,
                Instant.parse("2026-03-24T01:00:00Z"), "session-1", List.of("ROLE_ADMIN", "REPORT_EXPORT"), attributes);
    }

    private static AuthorizationStamp authorization() {
        return new AuthorizationStamp("USR001", "/reports/export", "GET", AuthorizationEffect.ALLOW, true,
                List.of("finance"), "policy-1", "v1", "SESSION", Instant.parse("2026-03-24T01:00:01Z"),
                List.of("ROLE_INTERPRETED"), List.of("INTERPRETED_AUTHORITY"), Map.of("policyId", "policy-1"));
    }

    private static RequestContextSnapshot request(String clientIp) {
        return new RequestContextSnapshot("/reports/export", "GET", clientIp, "JUnit", "session-1", "request-1",
                "/reports/export", null, false, Instant.parse("2026-03-24T01:00:02Z"));
    }

    private static String sha256(String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder builder = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            builder.append(String.format(Locale.ROOT, "%02x", b));
        }
        return builder.toString();
    }
}
