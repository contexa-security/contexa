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
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * R-12 and R-17 of docs/agent/운영모드-정상화-구현계획.md: a user named as one of Contexa's accounts is that account only
 * where the application's users sign in as Contexa's accounts. Under FULL with HOST_OWNED, Contexa's main chain signs the
 * application's users in from the application's store, so a user of a Contexa account's name is another person there,
 * and keeps a copy of its own.
 */
@DisplayName("미러의 Contexa 계정 판단은 앱 사용자가 Contexa 계정으로 로그인할 때뿐이다(R-12, R-17)")
class ContexaAccountsOfTheApplicationsSignInTest {

    private final UserRepository users = mock(UserRepository.class);

    @Test
    @DisplayName("FULL + HOST_OWNED: 앱 저장소로 로그인한 같은 이름의 사용자는 Contexa 계정이 아니라 사본을 가진다")
    void anApplicationsUserOfFullWithHostOwnedKeepsItsCopy() {
        DefaultBridgeUserMirrorSyncService service = service("FULL", SecurityOwnershipMode.HOST_OWNED);
        when(users.findOwnAccountId("USR001")).thenReturn(Optional.of(7L));
        savesWhatItIsGiven();

        BridgeUserMirrorSyncResult result = service.sync(stamp(), null, requestContext());

        verify(users).save(any(Users.class));
        assertThat(result.bridgeManaged()).isTrue();
    }

    @Test
    @DisplayName("FULL + HOST_OWNED에서 앱 저장소가 없어 Contexa 저장소가 로그인시키면 같은 이름은 그 계정이다")
    void anAccountOfFullWithHostOwnedWithoutAnApplicationsStoreIsTheAccount() {
        DefaultBridgeUserMirrorSyncService service = service("FULL", SecurityOwnershipMode.HOST_OWNED);
        service.setApplicationsUsersAreContexaAccounts(() -> true);
        when(users.findOwnAccountId("USR001")).thenReturn(Optional.of(7L));
        savesWhatItIsGiven();

        BridgeUserMirrorSyncResult result = service.sync(stamp(), null, requestContext());

        verify(users, never()).save(any(Users.class));
        assertThat(result.internalUserId()).isEqualTo(7L);
    }

    @Test
    @DisplayName("FULL + CONTEXA_OWNED: 같은 이름은 지금처럼 Contexa 계정이다")
    void anAccountOfFullWithContexaOwnedIsTheAccount() {
        DefaultBridgeUserMirrorSyncService service = service("FULL", SecurityOwnershipMode.CONTEXA_OWNED);
        when(users.findOwnAccountId("USR001")).thenReturn(Optional.of(7L));
        savesWhatItIsGiven();

        BridgeUserMirrorSyncResult result = service.sync(stamp(), null, requestContext());

        verify(users, never()).save(any(Users.class));
        assertThat(result.internalUserId()).isEqualTo(7L);
    }

    private DefaultBridgeUserMirrorSyncService service(String mode, SecurityOwnershipMode ownership) {
        BridgeUserProfileRepository profiles = mock(BridgeUserProfileRepository.class);
        when(profiles.findById(anyLong())).thenReturn(Optional.empty());
        when(profiles.save(any(BridgeUserProfile.class))).thenAnswer(invocation -> invocation.getArgument(0));
        BridgeProperties properties = new BridgeProperties();
        properties.setOwnership(ownership);
        properties.setEnvironment(new MockEnvironment()
                .withProperty(ContexaOperatingProfile.PROP_MODE, mode)
                .withProperty(ContexaOperatingProfile.PROP_OWNERSHIP, ownership.name()));
        return new DefaultBridgeUserMirrorSyncService(users, profiles, properties, new ObjectMapper(), null);
    }

    private void savesWhatItIsGiven() {
        when(users.findByBridgeSubjectKey(anyString())).thenReturn(Optional.empty());
        when(users.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationId(anyString(), anyString(), anyString()))
                .thenReturn(Optional.empty());
        when(users.save(any(Users.class))).thenAnswer(invocation -> {
            Users user = invocation.getArgument(0);
            user.setId(100L);
            return user;
        });
    }

    private static AuthenticationStamp stamp() {
        return new AuthenticationStamp("USR001", "Alice Kim", "USER", true, "SESSION", "SECURITY_CONTEXT", null, null,
                Instant.parse("2026-03-24T01:00:00Z"), "session-1", List.of("ROLE_USER"), Map.of());
    }

    private static RequestContextSnapshot requestContext() {
        return new RequestContextSnapshot("/orders", "GET", "10.0.0.10", "JUnit", "session-1", "request-1", "/orders",
                null, false, Instant.parse("2026-03-24T01:00:02Z"));
    }
}
