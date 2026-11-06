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
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The address a user's copy holds is where the step-up mails its codes. Once it is a real address, the address the
 * application shows next is not taken at once, since whoever holds the session can change the application's profile:
 * it waits until the user proves the address on record and then the address waiting, or an administrator enters one.
 * The copy takes only the address the user proved: one that waits since then stays waiting.
 */
class AnAddressOnRecordWaitsForItsUserTest {

    private final UserRepository users = mock(UserRepository.class);
    private final BridgeUserProfileRepository profiles = mock(BridgeUserProfileRepository.class);
    private final AtomicReference<Users> copy = new AtomicReference<>();
    private final AtomicReference<BridgeUserProfile> profile = new AtomicReference<>();
    private final DefaultBridgeUserMirrorSyncService sync = new DefaultBridgeUserMirrorSyncService(users, profiles,
            new BridgeProperties(), new ObjectMapper(), null);

    @BeforeEach
    void wire() {
        when(users.findByBridgeSubjectKey(anyString())).thenAnswer(call -> Optional.ofNullable(copy.get()));
        when(users.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationIdIsNull(anyString(), anyString()))
                .thenAnswer(call -> Optional.ofNullable(copy.get()));
        when(users.findById(anyLong())).thenAnswer(call -> Optional.ofNullable(copy.get()));
        when(users.findFirstByEmailIgnoreCase(anyString())).thenAnswer(call -> Optional.ofNullable(copy.get())
                .filter(user -> call.getArgument(0, String.class).equalsIgnoreCase(user.getEmail())));
        when(users.save(any(Users.class))).thenAnswer(call -> {
            Users user = call.getArgument(0);
            if (user.getId() == null) {
                user.setId(100L);
            }
            copy.set(user);
            return user;
        });
        when(profiles.findById(anyLong())).thenAnswer(call -> Optional.ofNullable(profile.get()));
        when(profiles.save(any(BridgeUserProfile.class))).thenAnswer(call -> {
            profile.set(call.getArgument(0));
            return call.getArgument(0);
        });
    }

    private void shows(String email) {
        Map<String, Object> attributes = email != null ? Map.of("email", email) : Map.of();
        sync.sync(new AuthenticationStamp("alice", "Alice", "USER", true, "FORM", "SECURITY_CONTEXT", null, null, null,
                        "s-1", List.of("ROLE_USER"), attributes), null,
                new RequestContextSnapshot("/profile", "POST", "198.51.100.9", "ua", "s-1", "r-1", "/profile", null,
                        false, Instant.now()));
    }

    private String address() {
        return copy.get().getEmail();
    }

    private String waiting() {
        return profile.get().getPendingEmail();
    }

    @Test
    @DisplayName("the first real address goes in at once")
    void theFirstRealAddress() {
        shows("Alice@Corp.Example");

        assertThat(address()).isEqualTo("alice@corp.example");
        assertThat(waiting()).isNull();
    }

    @Test
    @DisplayName("a made-up address gives way to the first real one at once")
    void aMadeUpAddressGivesWay() {
        shows(null);
        assertThat(address()).endsWith("@shadow.contexa.local");

        shows("alice@corp.example");

        assertThat(address()).isEqualTo("alice@corp.example");
        assertThat(waiting()).isNull();
    }

    @Test
    @DisplayName("another address the application shows waits, and the address on record stays")
    void anotherAddressWaits() {
        shows("alice@corp.example");

        shows("thief@evil.example");

        assertThat(address()).isEqualTo("alice@corp.example");
        assertThat(waiting()).isEqualTo("thief@evil.example");
    }

    @Test
    @DisplayName("the application showing the address on record again leaves nothing waiting")
    void theApplicationGoingBack() {
        shows("alice@corp.example");
        shows("thief@evil.example");

        shows("ALICE@corp.example");

        assertThat(address()).isEqualTo("alice@corp.example");
        assertThat(waiting()).isNull();
    }

    @Test
    @DisplayName("a newer address the application shows replaces the one waiting")
    void aNewerAddressReplacesTheOneWaiting() {
        shows("alice@corp.example");
        shows("first@corp.example");

        shows("second@corp.example");

        assertThat(address()).isEqualTo("alice@corp.example");
        assertThat(waiting()).isEqualTo("second@corp.example");
    }

    @Test
    @DisplayName("an application that stops showing an address leaves the address on record and what waits")
    void anApplicationThatStopsShowingAnAddress() {
        shows("alice@corp.example");
        shows("new@corp.example");

        shows(null);

        assertThat(address()).isEqualTo("alice@corp.example");
        assertThat(waiting()).isEqualTo("new@corp.example");
    }

    @Test
    @DisplayName("the address waiting is told to the step-up, which mails it its code")
    void theAddressWaitingIsTold() {
        shows("alice@corp.example");
        assertThat(sync.pendingEmail(100L)).isNull();

        shows("alice@home.example");

        assertThat(sync.pendingEmail(100L)).isEqualTo("alice@home.example");
        assertThat(sync.pendingEmail(null)).isNull();
    }

    @Test
    @DisplayName("the user's proof of the address waiting moves the copy to it")
    void theUsersProofTakesTheAddressWaiting() {
        shows("alice@corp.example");
        shows("alice@home.example");

        assertThat(sync.confirmPendingEmail(100L, "Alice@Home.example")).isTrue();

        assertThat(address()).isEqualTo("alice@home.example");
        assertThat(waiting()).isNull();
        shows("alice@home.example");
        assertThat(address()).isEqualTo("alice@home.example");
        assertThat(waiting()).isNull();
    }

    @Test
    @DisplayName("a proof of another address than the one waiting moves nothing")
    void aProofOfAnotherAddress() {
        shows("alice@corp.example");
        shows("alice@home.example");
        shows("thief@evil.example");

        assertThat(sync.confirmPendingEmail(100L, "alice@home.example")).isFalse();

        assertThat(address()).isEqualTo("alice@corp.example");
        assertThat(waiting()).isEqualTo("thief@evil.example");
    }

    @Test
    @DisplayName("a proof with nothing waiting changes nothing")
    void aProofWithNothingWaiting() {
        shows("alice@corp.example");

        assertThat(sync.confirmPendingEmail(100L, "alice@corp.example")).isFalse();
        assertThat(sync.confirmPendingEmail(null, "alice@corp.example")).isFalse();
        assertThat(sync.confirmPendingEmail(100L, null)).isFalse();

        assertThat(address()).isEqualTo("alice@corp.example");
    }

    @Test
    @DisplayName("an address another user holds is not taken, and it goes on waiting")
    void anAddressAnotherUserHolds() {
        shows("alice@corp.example");
        shows("bob@corp.example");
        Users bob = new Users();
        bob.setId(7L);
        bob.setEmail("bob@corp.example");
        when(users.findFirstByEmailIgnoreCase("bob@corp.example")).thenReturn(Optional.of(bob));

        assertThat(sync.confirmPendingEmail(100L, "bob@corp.example")).isFalse();

        assertThat(address()).isEqualTo("alice@corp.example");
        assertThat(waiting()).isEqualTo("bob@corp.example");
    }

    @Test
    @DisplayName("an address an administrator entered stands against the application's")
    void anAddressAnAdministratorEntered() {
        shows("alice@corp.example");
        copy.get().setEmail("entered@corp.example");

        shows("alice@corp.example");

        assertThat(address()).isEqualTo("entered@corp.example");
        assertThat(waiting()).isEqualTo("alice@corp.example");
    }
}
