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
import io.contexa.contexacommon.security.bridge.sync.BridgeUserShadowSyncResult;
import io.contexa.contexacommon.security.bridge.sync.DefaultBridgeUserShadowSyncService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class DefaultBridgeUserShadowSyncServiceTest {

    @Test
    void shouldProvisionBridgeManagedShadowUserAndProfile() {
        UserRepository userRepository = mock(UserRepository.class);
        BridgeUserProfileRepository bridgeUserProfileRepository = mock(BridgeUserProfileRepository.class);
        BridgeProperties properties = new BridgeProperties();
        DefaultBridgeUserShadowSyncService service = new DefaultBridgeUserShadowSyncService(
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

        BridgeUserShadowSyncResult result = service.sync(
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
        assertThat(savedUser.getOrganizationId()).isEqualTo("tenant-a");
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

        assertThat(result).isNotNull();
        assertThat(result.internalUserId()).isEqualTo(100L);
        assertThat(result.internalUsername()).startsWith("brg_");
        assertThat(result.externalSubjectId()).isEqualTo("USR001");
        assertThat(result.bridgeManaged()).isTrue();
        assertThat(result.externalAuthOnly()).isTrue();
        assertThat(result.created()).isTrue();
    }

    @Test
    void shouldSkipWriteWhenPayloadIsUnchangedWithinRefreshInterval() throws Exception {
        UserRepository userRepository = mock(UserRepository.class);
        BridgeUserProfileRepository bridgeUserProfileRepository = mock(BridgeUserProfileRepository.class);
        BridgeProperties properties = new BridgeProperties();
        properties.getSync().setMinRefreshIntervalSeconds(3600);

        DefaultBridgeUserShadowSyncService service = new DefaultBridgeUserShadowSyncService(
                userRepository,
                bridgeUserProfileRepository,
                properties,
                new ObjectMapper(),
                null
        );

        AuthenticationStamp authenticationStamp = authenticationStamp();
        AuthorizationStamp authorizationStamp = authorizationStamp();
        RequestContextSnapshot requestContext = requestContext();
        String bridgeSubjectKey = "brg_" + sha256("SESSION|tenant-a|USR001");

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
                .organizationId("tenant-a")
                .bridgeSubjectKey(bridgeSubjectKey)
                .lastLoginIp("10.0.0.10")
                .lastBridgedAt(LocalDateTime.now())
                .build();

        ObjectMapper objectMapper = new ObjectMapper();
        LinkedHashMap<String, Object> authoritiesPayload = new LinkedHashMap<>();
        authoritiesPayload.put("authenticationAuthorities", authenticationStamp.authorities());
        authoritiesPayload.put("effectiveRoles", authorizationStamp.effectiveRoles());
        authoritiesPayload.put("effectiveAuthorities", authorizationStamp.effectiveAuthorities());
        String authoritiesJson = objectMapper.writeValueAsString(authoritiesPayload);

        LinkedHashMap<String, Object> attributesPayload = new LinkedHashMap<>();
        attributesPayload.put("authenticationAttributes", authenticationStamp.attributes());
        attributesPayload.put("authorizationAttributes", authorizationStamp.attributes());
        attributesPayload.put("authorizationEffect", authorizationStamp.effect().name());
        attributesPayload.put("policyId", authorizationStamp.policyId());
        attributesPayload.put("policyVersion", authorizationStamp.policyVersion());
        attributesPayload.put("requestUri", requestContext.requestUri());
        attributesPayload.put("method", requestContext.method());
        String attributesJson = objectMapper.writeValueAsString(attributesPayload);

        BridgeUserProfile profile = BridgeUserProfile.builder()
                .userId(existingUser.getId())
                .user(existingUser)
                .sourceSystem("SESSION")
                .authenticationType("SESSION")
                .authenticationAssurance("HIGH")
                .mfaCompletedFromCustomer(true)
                .sessionId("session-1")
                .lastAuthoritiesJson(authoritiesJson)
                .lastAttributesJson(attributesJson)
                .lastSyncHash(sha256(authoritiesJson + "|" + attributesJson))
                .lastSyncedAt(LocalDateTime.now())
                .build();

        when(userRepository.findByBridgeSubjectKey(anyString())).thenReturn(Optional.of(existingUser));
        when(bridgeUserProfileRepository.findById(existingUser.getId())).thenReturn(Optional.of(profile));

        BridgeUserShadowSyncResult result = service.sync(authenticationStamp, authorizationStamp, requestContext);

        assertThat(result).isNotNull();
        assertThat(result.internalUserId()).isEqualTo(100L);
        assertThat(result.internalUsername()).isEqualTo(bridgeSubjectKey);
        assertThat(result.created()).isFalse();
        assertThat(result.updated()).isFalse();
        verify(userRepository, never()).save(any(Users.class));
        verify(bridgeUserProfileRepository, never()).save(any(BridgeUserProfile.class));
        verify(userRepository, times(1)).findByBridgeSubjectKey(anyString());
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
                        "organizationId", "tenant-a",
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
        return new RequestContextSnapshot(
                "/reports/export",
                "GET",
                "10.0.0.10",
                "JUnit",
                "session-1",
                "request-1",
                "/reports/export",
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

