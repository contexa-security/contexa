package io.contexa.contexacommon.security.bridge.sync;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.BridgeUserProfile;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.lang.Nullable;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.function.Consumer;

@Slf4j
@RequiredArgsConstructor
public class DefaultBridgeUserShadowSyncService implements BridgeUserShadowSyncService {

    private static final String USERS_WITH_AUTHORITIES_CACHE = "usersWithAuthorities";
    private static final ZoneId DEFAULT_ZONE = ZoneId.systemDefault();

    private final UserRepository userRepository;
    private final BridgeUserProfileRepository bridgeUserProfileRepository;
    private final BridgeProperties bridgeProperties;
    private final ObjectMapper objectMapper;
    @Nullable
    private final CacheManager cacheManager;

    @Override
    @Transactional
    public BridgeUserShadowSyncResult sync(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            RequestContextSnapshot requestContext
    ) {
        if (!bridgeProperties.getSync().isEnabled() || authenticationStamp == null || !authenticationStamp.authenticated()) {
            return null;
        }

        String externalSubjectId = normalize(authenticationStamp.principalId());
        if (externalSubjectId == null) {
            return null;
        }

        String authenticationSource = firstText(
                authenticationStamp.authenticationSource(),
                attribute(authenticationStamp.attributes(), "authenticationSource", "authSource", "sourceSystem"),
                "BRIDGE"
        );
        String organizationId = attribute(authenticationStamp.attributes(), "organizationId", "orgId", "tenantId");
        String bridgeSubjectKey = generateBridgeSubjectKey(authenticationSource, organizationId, externalSubjectId);
        LocalDateTime now = LocalDateTime.now();

        Optional<Users> existingUser = resolveUser(bridgeSubjectKey, externalSubjectId, authenticationSource, organizationId);
        BridgeUserProfile existingProfile = existingUser
                .flatMap(user -> user.getId() != null ? bridgeUserProfileRepository.findById(user.getId()) : Optional.empty())
                .orElse(null);

        SyncSnapshot syncSnapshot = buildSyncSnapshot(authenticationStamp, authorizationStamp, requestContext);
        if (shouldSkipSync(existingUser.orElse(null), existingProfile, authenticationStamp, requestContext, syncSnapshot, bridgeSubjectKey, externalSubjectId, authenticationSource, organizationId, now)) {
            Users user = existingUser.orElseThrow();
            return new BridgeUserShadowSyncResult(
                    user.getId(),
                    user.getUsername(),
                    externalSubjectId,
                    bridgeSubjectKey,
                    user.isBridgeManaged(),
                    user.isExternalAuthOnly(),
                    false,
                    false
            );
        }

        Users user = existingUser.orElseGet(Users::new);
        boolean created = user.getId() == null;
        boolean updated = applyUser(user, authenticationStamp, requestContext, bridgeSubjectKey, externalSubjectId, authenticationSource, organizationId, now);

        Users savedUser = userRepository.save(user);
        boolean profileUpdated = syncProfile(savedUser, existingProfile, syncSnapshot, now);
        evictUserCaches(savedUser);

        return new BridgeUserShadowSyncResult(
                savedUser.getId(),
                savedUser.getUsername(),
                externalSubjectId,
                bridgeSubjectKey,
                savedUser.isBridgeManaged(),
                savedUser.isExternalAuthOnly(),
                created,
                updated || profileUpdated
        );
    }

    private Optional<Users> resolveUser(
            String bridgeSubjectKey,
            String externalSubjectId,
            String authenticationSource,
            String organizationId
    ) {
        Optional<Users> byBridgeSubjectKey = userRepository.findByBridgeSubjectKey(bridgeSubjectKey);
        if (byBridgeSubjectKey.isPresent()) {
            return byBridgeSubjectKey;
        }
        if (organizationId != null) {
            return userRepository.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationId(
                    externalSubjectId,
                    authenticationSource,
                    organizationId
            );
        }
        return userRepository.findByExternalSubjectIdAndAuthenticationSourceAndOrganizationIdIsNull(
                externalSubjectId,
                authenticationSource
        );
    }

    private boolean shouldSkipSync(
            @Nullable Users existingUser,
            @Nullable BridgeUserProfile existingProfile,
            AuthenticationStamp authenticationStamp,
            RequestContextSnapshot requestContext,
            SyncSnapshot syncSnapshot,
            String bridgeSubjectKey,
            String externalSubjectId,
            String authenticationSource,
            String organizationId,
            LocalDateTime now
    ) {
        if (existingUser == null || existingProfile == null) {
            return false;
        }
        long minRefreshIntervalSeconds = bridgeProperties.getSync().getMinRefreshIntervalSeconds();
        if (minRefreshIntervalSeconds <= 0 || existingUser.getLastBridgedAt() == null) {
            return false;
        }
        if (existingUser.getLastBridgedAt().isBefore(now.minusSeconds(minRefreshIntervalSeconds))) {
            return false;
        }
        if (!syncSnapshot.syncHash().equals(existingProfile.getLastSyncHash())) {
            return false;
        }
        if (hasUserFieldChanges(existingUser, authenticationStamp, requestContext, bridgeSubjectKey, externalSubjectId, authenticationSource, organizationId)) {
            return false;
        }
        return true;
    }

    private boolean hasUserFieldChanges(
            Users user,
            AuthenticationStamp authenticationStamp,
            RequestContextSnapshot requestContext,
            String bridgeSubjectKey,
            String externalSubjectId,
            String authenticationSource,
            String organizationId
    ) {
        if (!user.isBridgeManaged() || !user.isExternalAuthOnly()) {
            return true;
        }
        if (!equalsNormalized(user.getBridgeSubjectKey(), bridgeSubjectKey)) {
            return true;
        }
        if (!equalsNormalized(user.getExternalSubjectId(), externalSubjectId)) {
            return true;
        }
        if (!equalsNormalized(user.getAuthenticationSource(), authenticationSource)) {
            return true;
        }
        if (wouldChangeString(user.getPrincipalType(), normalize(authenticationStamp.principalType()))) {
            return true;
        }
        if (wouldChangeString(user.getOrganizationId(), organizationId)) {
            return true;
        }
        if (wouldChangeString(user.getEmail(), resolveEmail(user, authenticationStamp, bridgeSubjectKey))) {
            return true;
        }
        if (wouldChangeString(user.getName(), firstText(authenticationStamp.displayName(), externalSubjectId))) {
            return true;
        }
        if (wouldChangeString(user.getPhone(), attribute(authenticationStamp.attributes(), "phone", "mobile", "mobileNumber"))) {
            return true;
        }
        if (wouldChangeString(user.getDepartment(), attribute(authenticationStamp.attributes(), "department", "team", "division"))) {
            return true;
        }
        if (wouldChangeString(user.getPosition(), attribute(authenticationStamp.attributes(), "position", "jobTitle", "title"))) {
            return true;
        }
        if (wouldChangeString(user.getProfileImageUrl(), attribute(authenticationStamp.attributes(), "profileImageUrl", "profile_image_url", "avatarUrl"))) {
            return true;
        }
        if (wouldChangeString(user.getLocale(), attribute(authenticationStamp.attributes(), "locale", "language", "lang"))) {
            return true;
        }
        if (wouldChangeString(user.getTimezone(), attribute(authenticationStamp.attributes(), "timezone", "timeZone"))) {
            return true;
        }
        if (wouldChangeString(user.getLastLoginIp(), requestContext != null ? requestContext.clientIp() : null)) {
            return true;
        }
        return false;
    }

    private boolean applyUser(
            Users user,
            AuthenticationStamp authenticationStamp,
            RequestContextSnapshot requestContext,
            String bridgeSubjectKey,
            String externalSubjectId,
            String authenticationSource,
            String organizationId,
            LocalDateTime now
    ) {
        boolean changed = false;
        if (user.getUsername() == null || user.getUsername().isBlank()) {
            user.setUsername(bridgeSubjectKey);
            changed = true;
        }
        if (user.getPassword() == null || user.getPassword().isBlank()) {
            user.setPassword("{noop}BRIDGE_EXTERNAL_ONLY::" + UUID.randomUUID());
            changed = true;
        }

        changed |= setIfChanged(user.getEmail(), resolveEmail(user, authenticationStamp, bridgeSubjectKey), user::setEmail);
        changed |= setIfChanged(user.getName(), firstText(authenticationStamp.displayName(), externalSubjectId), user::setName);
        changed |= setIfChanged(user.getPhone(), attribute(authenticationStamp.attributes(), "phone", "mobile", "mobileNumber"), user::setPhone);
        changed |= setIfChanged(user.getDepartment(), attribute(authenticationStamp.attributes(), "department", "team", "division"), user::setDepartment);
        changed |= setIfChanged(user.getPosition(), attribute(authenticationStamp.attributes(), "position", "jobTitle", "title"), user::setPosition);
        changed |= setIfChanged(user.getProfileImageUrl(), attribute(authenticationStamp.attributes(), "profileImageUrl", "profile_image_url", "avatarUrl"), user::setProfileImageUrl);
        changed |= setIfChanged(user.getLocale(), attribute(authenticationStamp.attributes(), "locale", "language", "lang"), user::setLocale);
        changed |= setIfChanged(user.getTimezone(), attribute(authenticationStamp.attributes(), "timezone", "timeZone"), user::setTimezone);
        changed |= setIfChanged(user.getExternalSubjectId(), externalSubjectId, user::setExternalSubjectId);
        changed |= setIfChanged(user.getAuthenticationSource(), authenticationSource, user::setAuthenticationSource);
        changed |= setIfChanged(user.getPrincipalType(), normalize(authenticationStamp.principalType()), user::setPrincipalType);
        changed |= setIfChanged(user.getOrganizationId(), organizationId, user::setOrganizationId);
        changed |= setIfChanged(user.getBridgeSubjectKey(), bridgeSubjectKey, user::setBridgeSubjectKey);

        if (!user.isBridgeManaged()) {
            user.setBridgeManaged(true);
            changed = true;
        }
        if (!user.isExternalAuthOnly()) {
            user.setExternalAuthOnly(true);
            changed = true;
        }
        if (!user.isEnabled()) {
            user.setEnabled(true);
            changed = true;
        }

        LocalDateTime lastLoginAt = toLocalDateTime(firstInstant(authenticationStamp.authenticationTime(), requestContext != null ? requestContext.collectedAt() : null));
        if (lastLoginAt != null && !lastLoginAt.equals(user.getLastLoginAt())) {
            user.setLastLoginAt(lastLoginAt);
            changed = true;
        }
        String lastLoginIp = requestContext != null ? normalize(requestContext.clientIp()) : null;
        changed |= setIfChanged(user.getLastLoginIp(), lastLoginIp, user::setLastLoginIp);

        if (!now.equals(user.getLastBridgedAt())) {
            user.setLastBridgedAt(now);
            changed = true;
        }
        return changed;
    }

    private SyncSnapshot buildSyncSnapshot(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            RequestContextSnapshot requestContext
    ) {
        String authoritiesJson = toJson(Map.of(
                "authenticationAuthorities", authenticationStamp.authorities(),
                "effectiveRoles", authorizationStamp != null ? authorizationStamp.effectiveRoles() : List.of(),
                "effectiveAuthorities", authorizationStamp != null ? authorizationStamp.effectiveAuthorities() : List.of()
        ));

        LinkedHashMap<String, Object> attributePayload = new LinkedHashMap<>();
        attributePayload.put("authenticationAttributes", authenticationStamp.attributes());
        attributePayload.put("authorizationAttributes", authorizationStamp != null ? authorizationStamp.attributes() : Map.of());
        attributePayload.put("authorizationEffect", authorizationStamp != null ? authorizationStamp.effect().name() : null);
        attributePayload.put("policyId", authorizationStamp != null ? authorizationStamp.policyId() : null);
        attributePayload.put("policyVersion", authorizationStamp != null ? authorizationStamp.policyVersion() : null);
        attributePayload.put("requestUri", requestContext != null ? requestContext.requestUri() : null);
        attributePayload.put("method", requestContext != null ? requestContext.method() : null);
        String attributesJson = toJson(attributePayload);

        return new SyncSnapshot(
                normalize(authenticationStamp.authenticationSource()),
                normalize(authenticationStamp.authenticationType()),
                normalize(authenticationStamp.authenticationAssurance()),
                authenticationStamp.mfaCompleted(),
                firstText(authenticationStamp.sessionId(), requestContext != null ? requestContext.sessionId() : null),
                authoritiesJson,
                attributesJson,
                hash(authoritiesJson + "|" + attributesJson)
        );
    }

    private boolean syncProfile(
            Users user,
            @Nullable BridgeUserProfile existingProfile,
            SyncSnapshot syncSnapshot,
            LocalDateTime now
    ) {
        BridgeUserProfile profile = existingProfile != null
                ? existingProfile
                : BridgeUserProfile.builder().user(user).userId(user.getId()).build();

        boolean changed = false;
        changed |= setIfChanged(profile.getSourceSystem(), syncSnapshot.sourceSystem(), profile::setSourceSystem);
        changed |= setIfChanged(profile.getAuthenticationType(), syncSnapshot.authenticationType(), profile::setAuthenticationType);
        changed |= setIfChanged(profile.getAuthenticationAssurance(), syncSnapshot.authenticationAssurance(), profile::setAuthenticationAssurance);
        changed |= setIfChanged(profile.getMfaCompletedFromCustomer(), syncSnapshot.mfaCompletedFromCustomer(), profile::setMfaCompletedFromCustomer);
        changed |= setIfChanged(profile.getSessionId(), syncSnapshot.sessionId(), profile::setSessionId);
        changed |= setIfChanged(profile.getLastAuthoritiesJson(), syncSnapshot.authoritiesJson(), profile::setLastAuthoritiesJson);
        changed |= setIfChanged(profile.getLastAttributesJson(), syncSnapshot.attributesJson(), profile::setLastAttributesJson);
        changed |= setIfChanged(profile.getLastSyncHash(), syncSnapshot.syncHash(), profile::setLastSyncHash);

        if (!now.equals(profile.getLastSyncedAt())) {
            profile.setLastSyncedAt(now);
            changed = true;
        }

        if (changed || profile.getUser() == null) {
            profile.setUser(user);
            profile.setUserId(user.getId());
            bridgeUserProfileRepository.save(profile);
            return true;
        }
        return false;
    }

    private String resolveEmail(Users user, AuthenticationStamp authenticationStamp, String bridgeSubjectKey) {
        String email = normalize(attribute(authenticationStamp.attributes(), "email", "mail", "userEmail"));
        if (email == null) {
            return firstText(user.getEmail(), syntheticEmail(bridgeSubjectKey));
        }
        return email.toLowerCase(Locale.ROOT);
    }

    private String syntheticEmail(String bridgeSubjectKey) {
        return bridgeSubjectKey + "@" + bridgeProperties.getSync().getSyntheticEmailDomain();
    }

    private void evictUserCaches(Users user) {
        if (cacheManager == null || user == null) {
            return;
        }
        Cache cache = cacheManager.getCache(USERS_WITH_AUTHORITIES_CACHE);
        if (cache == null) {
            return;
        }
        if (user.getUsername() != null) {
            cache.evict(user.getUsername());
        }
        if (user.getId() != null) {
            cache.evict(user.getId());
        }
    }

    private String attribute(Map<String, Object> attributes, String... keys) {
        if (attributes == null || attributes.isEmpty()) {
            return null;
        }
        for (String key : keys) {
            Object value = attributes.get(key);
            String normalized = normalize(value != null ? value.toString() : null);
            if (normalized != null) {
                return normalized;
            }
        }
        return null;
    }

    private LocalDateTime toLocalDateTime(Instant instant) {
        if (instant == null) {
            return null;
        }
        return LocalDateTime.ofInstant(instant, DEFAULT_ZONE);
    }

    private Instant firstInstant(Instant primary, Instant fallback) {
        return primary != null ? primary : fallback;
    }

    private String firstText(String... values) {
        for (String value : values) {
            String normalized = normalize(value);
            if (normalized != null) {
                return normalized;
            }
        }
        return null;
    }

    private String normalize(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim();
        return normalized.isBlank() ? null : normalized;
    }

    private boolean equalsNormalized(String currentValue, String nextValue) {
        String normalizedCurrent = normalize(currentValue);
        String normalizedNext = normalize(nextValue);
        if (normalizedCurrent == null) {
            return normalizedNext == null;
        }
        return normalizedCurrent.equals(normalizedNext);
    }

    private boolean wouldChangeString(String currentValue, String nextValue) {
        String normalizedNext = normalize(nextValue);
        if (normalizedNext == null) {
            return false;
        }
        return !equalsNormalized(currentValue, normalizedNext);
    }

    private boolean setIfChanged(String currentValue, String newValue, Consumer<String> consumer) {
        String normalizedNewValue = normalize(newValue);
        if (normalizedNewValue == null) {
            return false;
        }
        if (!normalizedNewValue.equals(currentValue)) {
            consumer.accept(normalizedNewValue);
            return true;
        }
        return false;
    }

    private boolean setIfChanged(Boolean currentValue, Boolean newValue, Consumer<Boolean> consumer) {
        if (newValue == null) {
            return false;
        }
        if (!newValue.equals(currentValue)) {
            consumer.accept(newValue);
            return true;
        }
        return false;
    }

    private String toJson(Object payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException ex) {
            log.error("[Bridge] Failed to serialize bridge user shadow payload", ex);
            return "{}";
        }
    }

    private String generateBridgeSubjectKey(String authenticationSource, String organizationId, String externalSubjectId) {
        String canonical = String.join("|",
                normalize(authenticationSource) != null ? normalize(authenticationSource) : "BRIDGE",
                normalize(organizationId) != null ? normalize(organizationId) : "GLOBAL",
                externalSubjectId
        );
        return "brg_" + hash(canonical);
    }

    private String hash(String value) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] digest = messageDigest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm is unavailable", ex);
        }
    }

    private record SyncSnapshot(
            String sourceSystem,
            String authenticationType,
            String authenticationAssurance,
            Boolean mfaCompletedFromCustomer,
            String sessionId,
            String authoritiesJson,
            String attributesJson,
            String syncHash
    ) {
    }
}


