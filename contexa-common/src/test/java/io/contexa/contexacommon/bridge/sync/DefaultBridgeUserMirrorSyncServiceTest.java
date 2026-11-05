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
import io.contexa.contexacommon.security.bridge.sync.BridgeUserEmailProvider;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserMirrorSyncService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class DefaultBridgeUserMirrorSyncServiceTest {

    @Test
    void shouldProvisionBridgeManagedShadowUserAndProfile() {
        UserRepository userRepository = mock(UserRepository.class);
        BridgeUserProfileRepository bridgeUserProfileRepository = mock(BridgeUserProfileRepository.class);
        BridgeProperties properties = new BridgeProperties();
        DefaultBridgeUserMirrorSyncService service = new DefaultBridgeUserMirrorSyncService(
                userRepository,
                bridgeUserProfileRepository,
                properties,
                new ObjectMapper(),
                null
        );

        when(userRepository.findByBridgeSubjectKey(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationId(anyString(), anyString(), anyString())).thenReturn(Optional.empty());
        when(bridgeUserProfileRepository.findById(anyLong())).thenReturn(Optional.empty());
        when(userRepository.save(any(Users.class))).thenAnswer(invocation -> {
            Users user = invocation.getArgument(0);
            user.setId(100L);
            return user;
        });
        when(bridgeUserProfileRepository.save(any(BridgeUserProfile.class))).thenAnswer(invocation -> invocation.getArgument(0));

        BridgeUserMirrorSyncResult result = service.sync(
                authenticationStamp(),
                authorizationStamp(),
                requestContext()
        );

        ArgumentCaptor<Users> userCaptor = ArgumentCaptor.forClass(Users.class);
        verify(userRepository).save(userCaptor.capture());
        Users savedUser = userCaptor.getValue();
        assertThat(savedUser.getUsername()).startsWith("brg_");
        assertThat(savedUser.isBridgeManaged()).isTrue();
        assertThat(savedUser.isExternalAuthOnly()).isTrue();
        assertThat(savedUser.getExternalSubjectId()).isEqualTo("USR001");
        assertThat(savedUser.getAuthenticationSource()).isEqualTo("SESSION");
        assertThat(savedUser.getOrganizationId()).isEqualTo("org-a");
        assertThat(savedUser.getDepartment()).isEqualTo("finance");
        assertThat(savedUser.getPosition()).isEqualTo("manager");
        assertThat(savedUser.getEmail()).endsWith("@shadow.contexa.local");
        assertThat(savedUser.getLastLoginIp()).isEqualTo("10.0.0.10");

        ArgumentCaptor<BridgeUserProfile> profileCaptor = ArgumentCaptor.forClass(BridgeUserProfile.class);
        verify(bridgeUserProfileRepository).save(profileCaptor.capture());
        BridgeUserProfile profile = profileCaptor.getValue();
        assertThat(profile.getSourceSystem()).isEqualTo("SESSION");
        assertThat(profile.getAuthenticationType()).isEqualTo("SESSION");
        assertThat(profile.getAuthenticationAssurance()).isEqualTo("HIGH");
        assertThat(profile.getLastAuthoritiesJson()).contains("ROLE_ADMIN");
        assertThat(profile.getLastAttributesJson()).contains("tenant-a");
        // A new profile keeps a null id so that JPA persists it; @MapsId derives the id from the user.
        assertThat(profile.getUserId()).isNull();
        assertThat(profile.getUser()).isSameAs(userCaptor.getValue());

        assertThat(result).isNotNull();
        assertThat(result.internalUserId()).isEqualTo(100L);
        assertThat(result.internalUsername()).startsWith("brg_");
        assertThat(result.externalSubjectId()).isEqualTo("USR001");
        assertThat(result.bridgeManaged()).isTrue();
        assertThat(result.externalAuthOnly()).isTrue();
        assertThat(result.created()).isTrue();
    }

    private static DefaultBridgeUserMirrorSyncService syncing(UserRepository users, BridgeUserProfileRepository profiles,
                                                              BridgeUserEmailProvider provider) {
        DefaultBridgeUserMirrorSyncService service = new DefaultBridgeUserMirrorSyncService(users, profiles,
                new BridgeProperties(), new ObjectMapper(), null);
        service.setEmailProvider(provider);
        when(users.findByBridgeSubjectKey(anyString())).thenReturn(Optional.empty());
        when(users.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationId(anyString(), anyString(), anyString()))
                .thenReturn(Optional.empty());
        when(users.save(any(Users.class))).thenAnswer(invocation -> {
            Users user = invocation.getArgument(0);
            user.setId(100L);
            return user;
        });
        when(profiles.findById(anyLong())).thenReturn(Optional.empty());
        when(profiles.save(any(BridgeUserProfile.class))).thenAnswer(invocation -> invocation.getArgument(0));
        return service;
    }

    @Test
    void q1_theApplicationTellsTheAddressOfAUserWhoCarriesNone() {
        UserRepository users = mock(UserRepository.class);
        DefaultBridgeUserMirrorSyncService service = syncing(users, mock(BridgeUserProfileRepository.class),
                principal -> "USR001".equals(principal) ? "Real.Person@corp.example" : null);

        service.sync(authenticationStamp(), authorizationStamp(), requestContext());

        ArgumentCaptor<Users> saved = ArgumentCaptor.forClass(Users.class);
        verify(users).save(saved.capture());
        assertThat(saved.getValue().getEmail()).isEqualTo("real.person@corp.example");
    }

    @Test
    void q1_anApplicationWithNoAddressLeavesAMadeUpOne() {
        UserRepository users = mock(UserRepository.class);
        DefaultBridgeUserMirrorSyncService service = syncing(users, mock(BridgeUserProfileRepository.class), principal -> null);

        service.sync(authenticationStamp(), authorizationStamp(), requestContext());

        ArgumentCaptor<Users> saved = ArgumentCaptor.forClass(Users.class);
        verify(users).save(saved.capture());
        assertThat(saved.getValue().getEmail()).endsWith("@shadow.contexa.local");
    }

    @Test
    void q1_anAddressAnAdministratorEnteredStands() {
        UserRepository users = mock(UserRepository.class);
        boolean[] asked = {false};
        DefaultBridgeUserMirrorSyncService service = syncing(users, mock(BridgeUserProfileRepository.class), principal -> {
            asked[0] = true;
            return "other@corp.example";
        });
        Users existing = new Users();
        existing.setId(100L);
        existing.setEmail("entered@corp.example");
        when(users.findByBridgeSubjectKey(anyString())).thenReturn(Optional.of(existing));

        service.sync(authenticationStamp(), authorizationStamp(), requestContext());

        assertThat(asked[0]).isFalse();
        assertThat(existing.getEmail()).isEqualTo("entered@corp.example");
    }

    @Test
    void q1_aProviderThatFailsStopsNothing() {
        UserRepository users = mock(UserRepository.class);
        DefaultBridgeUserMirrorSyncService service = syncing(users, mock(BridgeUserProfileRepository.class), principal -> {
            throw new IllegalStateException("directory down");
        });

        BridgeUserMirrorSyncResult result = service.sync(authenticationStamp(), authorizationStamp(), requestContext());

        assertThat(result).isNotNull();
    }

    @Test
    void shouldSkipWriteWhenPayloadIsUnchangedWithinRefreshInterval() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        BridgeUserProfileRepository bridgeUserProfileRepository = mock(BridgeUserProfileRepository.class);
        BridgeProperties properties = new BridgeProperties();
        properties.getSync().setMinRefreshIntervalSeconds(3600);

        DefaultBridgeUserMirrorSyncService service = new DefaultBridgeUserMirrorSyncService(
                userRepository,
                bridgeUserProfileRepository,
                properties,
                new ObjectMapper(),
                null
        );

        AuthenticationStamp authenticationStamp = authenticationStamp();
        AuthorizationStamp authorizationStamp = authorizationStamp();
        RequestContextSnapshot requestContext = requestContext();
        String bridgeSubjectKey = "brg_" + sha256("SESSION|org-a|USR001");

        Users existingUser = Users.builder()
                .id(100L)
                .username(bridgeSubjectKey)
                .password("{noop}BRIDGE_EXTERNAL_ONLY::seed")
                .name("Alice Kim")
                .email(bridgeSubjectKey + "@shadow.contexa.local")
                .department("finance")
                .position("manager")
                .enabled(true)
                .bridgeManaged(true)
                .externalAuthOnly(true)
                .externalSubjectId("USR001")
                .authenticationSource("SESSION")
                .principalType("USER")
                .organizationId("org-a")
                .bridgeSubjectKey(bridgeSubjectKey)
                .lastLoginIp("10.0.0.10")
                .lastBridgedAt(LocalDateTime.now())
                .build();

        BridgeUserProfile profile = BridgeUserProfile.builder()
                .userId(existingUser.getId())
                .user(existingUser)
                .sourceSystem("SESSION")
                .authenticationType("SESSION")
                .authenticationAssurance("HIGH")
                .mfaCompletedFromCustomer(true)
                .sessionId("session-1")
                .lastAuthoritiesJson("{}")
                .lastAttributesJson("{}")
                .lastSyncHash(extractSyncHash(service, authenticationStamp, authorizationStamp, requestContext))
                .lastSyncedAt(LocalDateTime.now())
                .build();

        when(userRepository.findByBridgeSubjectKey(anyString())).thenReturn(Optional.of(existingUser));
        when(bridgeUserProfileRepository.findById(existingUser.getId())).thenReturn(Optional.of(profile));

        BridgeUserMirrorSyncResult result = service.sync(authenticationStamp, authorizationStamp, requestContext);

        assertThat(result).isNotNull();
        assertThat(result.internalUserId()).isEqualTo(100L);
        assertThat(result.internalUsername()).isEqualTo(bridgeSubjectKey);
        assertThat(result.created()).isFalse();
        assertThat(result.updated()).isFalse();
        verify(userRepository, never()).save(any(Users.class));
        verify(bridgeUserProfileRepository, never()).save(any(BridgeUserProfile.class));
        verify(userRepository, times(1)).findByBridgeSubjectKey(anyString());
    }

    @Test
    void shouldSkipWriteWhenOnlyRequestUriAndMethodChangeWithinRefreshInterval() {
        UserRepository userRepository = mock(UserRepository.class);
        BridgeUserProfileRepository bridgeUserProfileRepository = mock(BridgeUserProfileRepository.class);
        BridgeProperties properties = new BridgeProperties();
        properties.getSync().setMinRefreshIntervalSeconds(60);
        DefaultBridgeUserMirrorSyncService service = new DefaultBridgeUserMirrorSyncService(
                userRepository,
                bridgeUserProfileRepository,
                properties,
                new ObjectMapper(),
                null
        );

        AtomicReference<Users> storedUser = new AtomicReference<>();
        AtomicReference<BridgeUserProfile> storedProfile = new AtomicReference<>();
        when(userRepository.findByBridgeSubjectKey(anyString()))
                .thenAnswer(invocation -> Optional.ofNullable(storedUser.get()));
        when(userRepository.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationId(anyString(), anyString(), anyString()))
                .thenReturn(Optional.empty());
        when(bridgeUserProfileRepository.findById(anyLong()))
                .thenAnswer(invocation -> Optional.ofNullable(storedProfile.get()));
        when(userRepository.save(any(Users.class))).thenAnswer(invocation -> {
            Users user = invocation.getArgument(0);
            user.setId(100L);
            storedUser.set(user);
            return user;
        });
        when(bridgeUserProfileRepository.save(any(BridgeUserProfile.class))).thenAnswer(invocation -> {
            BridgeUserProfile profile = invocation.getArgument(0);
            storedProfile.set(profile);
            return profile;
        });

        BridgeUserMirrorSyncResult first = service.sync(authenticationStamp(), authorizationStamp(), requestContext());
        BridgeUserMirrorSyncResult second = service.sync(
                authenticationStamp(),
                authorizationStamp(),
                requestContext("/reports/summary", "POST", "request-2")
        );

        assertThat(first.created()).isTrue();
        assertThat(second.internalUserId()).isEqualTo(100L);
        assertThat(second.created()).isFalse();
        assertThat(second.updated()).isFalse();
        verify(userRepository, times(1)).save(any(Users.class));
        verify(bridgeUserProfileRepository, times(1)).save(any(BridgeUserProfile.class));
        assertThat(storedProfile.get().getLastAttributesJson())
                .contains("tenant-a")
                .doesNotContain("/reports/export");
    }

    @Test
    void shouldNotUseTenantIdAsOrganizationScope() {
        UserRepository userRepository = mock(UserRepository.class);
        BridgeUserProfileRepository bridgeUserProfileRepository = mock(BridgeUserProfileRepository.class);
        BridgeProperties properties = new BridgeProperties();
        DefaultBridgeUserMirrorSyncService service = new DefaultBridgeUserMirrorSyncService(
                userRepository,
                bridgeUserProfileRepository,
                properties,
                new ObjectMapper(),
                null
        );

        when(userRepository.findByBridgeSubjectKey(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationIdIsNull(anyString(), anyString()))
                .thenReturn(Optional.empty());
        when(bridgeUserProfileRepository.findById(anyLong())).thenReturn(Optional.empty());
        when(userRepository.save(any(Users.class))).thenAnswer(invocation -> {
            Users user = invocation.getArgument(0);
            user.setId(101L);
            return user;
        });
        when(bridgeUserProfileRepository.save(any(BridgeUserProfile.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AuthenticationStamp authenticationStamp = new AuthenticationStamp(
                "USR002",
                "Bob Lee",
                "USER",
                true,
                "SESSION",
                "SESSION",
                "HIGH",
                true,
                Instant.parse("2026-03-24T01:00:00Z"),
                "session-2",
                List.of("ROLE_USER"),
                Map.of(
                        "tenantId", "tenant-only",
                        "department", "finance"
                )
        );

        service.sync(authenticationStamp, authorizationStamp(), requestContext());

        ArgumentCaptor<Users> userCaptor = ArgumentCaptor.forClass(Users.class);
        verify(userRepository).save(userCaptor.capture());
        Users savedUser = userCaptor.getValue();
        assertThat(savedUser.getOrganizationId()).isNull();
        assertThat(savedUser.getBridgeSubjectKey()).isEqualTo("brg_" + sha256("SESSION|GLOBAL|USR002"));
        verify(userRepository).findByExternalSubjectIdAndAuthenticationSourceAndOrganizationIdIsNull("USR002", "SESSION");
        verify(userRepository, never()).findByExternalSubjectIdAndAuthenticationSourceAndOrganizationId(anyString(), anyString(), eq("tenant-only"));
    }

    private String extractSyncHash(
            DefaultBridgeUserMirrorSyncService service,
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            RequestContextSnapshot requestContext
    ) throws Exception {
        Method buildSyncSnapshot = DefaultBridgeUserMirrorSyncService.class.getDeclaredMethod(
                "buildSyncSnapshot",
                AuthenticationStamp.class,
                AuthorizationStamp.class,
                RequestContextSnapshot.class
        );
        buildSyncSnapshot.setAccessible(true);
        Object syncSnapshot = buildSyncSnapshot.invoke(service, authenticationStamp, authorizationStamp, requestContext);
        Method syncHash = syncSnapshot.getClass().getDeclaredMethod("syncHash");
        syncHash.setAccessible(true);
        return (String) syncHash.invoke(syncSnapshot);
    }

    /**
     * Exception tests 2026-11-03 (ownership harness): a value from the host longer than its column (a distinguished
     * name as the department, a phone number with an extension, a signed avatar URL, a long subject as the name)
     * failed the whole copy of the user on every request, with an error and a stack trace each time, and the user
     * stayed without a copy (no step-up factor, no identity-bound feature). The copy keeps the user; each value is cut
     * to its column.
     */
    @Test
    void valuesLongerThanTheirColumnsAreCutNotFailed() {
        UserRepository userRepository = mock(UserRepository.class);
        BridgeUserProfileRepository bridgeUserProfileRepository = mock(BridgeUserProfileRepository.class);
        DefaultBridgeUserMirrorSyncService service = new DefaultBridgeUserMirrorSyncService(
                userRepository, bridgeUserProfileRepository, new BridgeProperties(), new ObjectMapper(), null);
        when(userRepository.findByBridgeSubjectKey(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationIdIsNull(anyString(), anyString()))
                .thenReturn(Optional.empty());
        when(bridgeUserProfileRepository.findById(anyLong())).thenReturn(Optional.empty());
        when(userRepository.save(any(Users.class))).thenAnswer(invocation -> {
            Users user = invocation.getArgument(0);
            user.setId(7L);
            return user;
        });
        when(bridgeUserProfileRepository.save(any(BridgeUserProfile.class))).thenAnswer(invocation -> invocation.getArgument(0));
        String subject = "cn=" + "a".repeat(150) + ",dc=corp";
        AuthenticationStamp stamp = new AuthenticationStamp(subject, null, "U".repeat(80), true, "S".repeat(120),
                "SESSION", "HIGH", true, Instant.parse("2026-03-24T01:00:00Z"), "session-1", List.of("ROLE_USER"),
                Map.of("department", "OU=" + "d".repeat(200), "position", "p".repeat(200),
                        "phone", "+82-2-1234-5678 ext. 99999", "avatarUrl", "https://cdn.example/" + "x".repeat(600),
                        "locale", "ko-KR-u-ca-hanja", "timezone", "Asia/" + "z".repeat(80),
                        "email", "e".repeat(300) + "@corp.example"));

        BridgeUserMirrorSyncResult result = service.sync(stamp, authorizationStamp(), requestContext());

        ArgumentCaptor<Users> saved = ArgumentCaptor.forClass(Users.class);
        verify(userRepository).save(saved.capture());
        Users user = saved.getValue();
        assertThat(result).as("the user is mirrored").isNotNull();
        assertThat(user.getName()).hasSizeLessThanOrEqualTo(100).startsWith("cn=");
        assertThat(user.getDepartment()).hasSize(100);
        assertThat(user.getPosition()).hasSize(100);
        assertThat(user.getPhone()).hasSizeLessThanOrEqualTo(20);
        assertThat(user.getProfileImageUrl()).hasSizeLessThanOrEqualTo(500);
        assertThat(user.getLocale()).hasSizeLessThanOrEqualTo(10);
        assertThat(user.getTimezone()).hasSizeLessThanOrEqualTo(50);
        assertThat(user.getAuthenticationSource()).hasSizeLessThanOrEqualTo(100);
        assertThat(user.getPrincipalType()).hasSizeLessThanOrEqualTo(50);
        assertThat(user.getEmail()).as("an address longer than the column is not kept, a made-up one stands in")
                .hasSizeLessThanOrEqualTo(255).endsWith("@shadow.contexa.local");
        assertThat(user.getExternalSubjectId()).isEqualTo(subject);
    }

    @Test
    void aCutValueDoesNotMakeEveryRequestAnUpdate() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        BridgeUserProfileRepository bridgeUserProfileRepository = mock(BridgeUserProfileRepository.class);
        BridgeProperties properties = new BridgeProperties();
        properties.getSync().setMinRefreshIntervalSeconds(3600);
        DefaultBridgeUserMirrorSyncService service = new DefaultBridgeUserMirrorSyncService(
                userRepository, bridgeUserProfileRepository, properties, new ObjectMapper(), null);
        AtomicReference<Users> stored = new AtomicReference<>();
        AtomicReference<BridgeUserProfile> storedProfile = new AtomicReference<>();
        when(userRepository.findByBridgeSubjectKey(anyString())).thenAnswer(invocation -> Optional.ofNullable(stored.get()));
        when(userRepository.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationIdIsNull(anyString(), anyString()))
                .thenAnswer(invocation -> Optional.ofNullable(stored.get()));
        when(bridgeUserProfileRepository.findById(anyLong())).thenAnswer(invocation -> Optional.ofNullable(storedProfile.get()));
        when(userRepository.save(any(Users.class))).thenAnswer(invocation -> {
            Users user = invocation.getArgument(0);
            user.setId(7L);
            stored.set(user);
            return user;
        });
        when(bridgeUserProfileRepository.save(any(BridgeUserProfile.class))).thenAnswer(invocation -> {
            BridgeUserProfile profile = invocation.getArgument(0);
            storedProfile.set(profile);
            return profile;
        });
        AuthenticationStamp stamp = new AuthenticationStamp("USR009", "Alice", "USER", true, "SESSION", "SESSION", "HIGH",
                true, Instant.parse("2026-03-24T01:00:00Z"), "session-1", List.of("ROLE_USER"),
                Map.of("department", "OU=" + "d".repeat(200)));

        service.sync(stamp, authorizationStamp(), requestContext());
        service.sync(stamp, authorizationStamp(), requestContext());

        verify(userRepository, times(1)).save(any(Users.class));
    }

    @Test
    void aSubjectLongerThanItsColumnIsNotMirroredAndDoesNotFail() {
        UserRepository userRepository = mock(UserRepository.class);
        DefaultBridgeUserMirrorSyncService service = new DefaultBridgeUserMirrorSyncService(
                userRepository, mock(BridgeUserProfileRepository.class), new BridgeProperties(), new ObjectMapper(), null);
        AuthenticationStamp stamp = new AuthenticationStamp("s".repeat(300), "Alice", "USER", true, "SESSION", "SESSION",
                "HIGH", true, Instant.parse("2026-03-24T01:00:00Z"), "session-1", List.of("ROLE_USER"), Map.of());

        BridgeUserMirrorSyncResult result = service.sync(stamp, authorizationStamp(), requestContext());

        assertThat(result).isNull();
        verify(userRepository, never()).save(any(Users.class));
    }

    private AuthenticationStamp authenticationStamp() {
        return new AuthenticationStamp(
                "USR001",
                "Alice Kim",
                "USER",
                true,
                "SESSION",
                "SESSION",
                "HIGH",
                true,
                Instant.parse("2026-03-24T01:00:00Z"),
                "session-1",
                List.of("ROLE_ADMIN", "REPORT_EXPORT"),
                Map.of(
                        "tenantId", "tenant-a",
                        "organizationId", "org-a",
                        "department", "finance",
                        "position", "manager"
                )
        );
    }

    private AuthorizationStamp authorizationStamp() {
        return new AuthorizationStamp(
                "USR001",
                "/reports/export",
                "GET",
                AuthorizationEffect.ALLOW,
                true,
                List.of("finance"),
                "policy-1",
                "v1",
                "SESSION",
                Instant.parse("2026-03-24T01:00:01Z"),
                List.of("ROLE_ADMIN"),
                List.of("REPORT_EXPORT"),
                Map.of("policyId", "policy-1")
        );
    }

    private RequestContextSnapshot requestContext() {
        return requestContext("/reports/export", "GET", "request-1");
    }

    private RequestContextSnapshot requestContext(String requestUri, String method, String requestId) {
        return new RequestContextSnapshot(
                requestUri,
                method,
                "10.0.0.10",
                "JUnit",
                "session-1",
                requestId,
                requestUri,
                null,
                false,
                Instant.parse("2026-03-24T01:00:02Z")
        );
    }

    private String sha256(String value) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] digest = messageDigest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
