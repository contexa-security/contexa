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
package io.contexa.contexacommon.security.bridge.sync;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.BridgeUserProfile;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.operating.OwnershipBehaviour;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

@Slf4j
@RequiredArgsConstructor
public class DefaultBridgeUserMirrorSyncService implements BridgeUserMirrorSyncService {

    private static final BCryptPasswordEncoder SHADOW_PASSWORD_ENCODER = new BCryptPasswordEncoder();

    private static final String USERS_WITH_AUTHORITIES_CACHE = "usersWithAuthorities";
    private static final ZoneId DEFAULT_ZONE = ZoneId.systemDefault();

    private final UserRepository userRepository;
    private final BridgeUserProfileRepository bridgeUserProfileRepository;
    private final BridgeProperties bridgeProperties;
    private final ObjectMapper objectMapper;
    @Nullable
    private final CacheManager cacheManager;

    // The columns of users (META-INF/contexa/db/schema.sql).
    private static final int TEXT_MAX = 100;
    private static final int LONG_TEXT_MAX = 255;
    private static final int PHONE_MAX = 20;
    private static final int PROFILE_IMAGE_MAX = 500;
    private static final int LOCALE_MAX = 10;
    private static final int TIMEZONE_MAX = 50;
    private static final int PRINCIPAL_TYPE_MAX = 50;

    private final Set<String> tooLongSubjects = ConcurrentHashMap.newKeySet();
    private BridgeUserEmailProvider emailProvider;

    /** Q-1: where the application tells the address of a user who carries none. */
    public void setEmailProvider(BridgeUserEmailProvider emailProvider) {
        this.emailProvider = emailProvider;
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public BridgeUserMirrorSyncResult sync(
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
        if (externalSubjectId.length() > LONG_TEXT_MAX) {
            // The subject is the key the copy is found by: cut, it would be another user's. No copy is made (the
            // user has no step-up factor of its own then); said once, not on every request.
            if (tooLongSubjects.size() < 1000 && tooLongSubjects.add(Integer.toHexString(externalSubjectId.hashCode()))) {
                log.warn("[Bridge] No user copy for a subject longer than {} characters ({} characters)", LONG_TEXT_MAX,
                        externalSubjectId.length());
            }
            return null;
        }

        Optional<Long> ownAccount = ownAccount(externalSubjectId);
        if (ownAccount.isPresent()) {
            return new BridgeUserMirrorSyncResult(ownAccount.get(), externalSubjectId, externalSubjectId, null, false, false, false, false);
        }

        String authenticationSource = fit(firstText(
                authenticationStamp.authenticationSource(),
                attribute(authenticationStamp.attributes(), "authenticationSource", "authSource", "sourceSystem"),
                "BRIDGE"
        ), TEXT_MAX);
        String organizationId = fit(attribute(authenticationStamp.attributes(), "organizationId", "orgId"), LONG_TEXT_MAX);
        String bridgeSubjectKey = generateBridgeSubjectKey(authenticationSource, organizationId, externalSubjectId);
        LocalDateTime now = LocalDateTime.now();

        Optional<Users> existingUser = resolveUser(bridgeSubjectKey, externalSubjectId, authenticationSource, organizationId);
        BridgeUserProfile existingProfile = existingUser
                .flatMap(user -> user.getId() != null ? bridgeUserProfileRepository.findById(user.getId()) : Optional.empty())
                .orElse(null);

        SyncSnapshot syncSnapshot = buildSyncSnapshot(authenticationStamp, authorizationStamp, requestContext);
        if (shouldSkipSync(existingUser.orElse(null), existingProfile, authenticationStamp, requestContext, syncSnapshot, bridgeSubjectKey, externalSubjectId, authenticationSource, organizationId, now)) {
            Users user = existingUser.orElseThrow();
            return new BridgeUserMirrorSyncResult(
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
        EmailChange email = resolveEmail(user, existingProfile, authenticationStamp, bridgeSubjectKey);
        boolean updated = applyUser(user, authenticationStamp, requestContext, bridgeSubjectKey, externalSubjectId, authenticationSource, organizationId, email, now);

        Users savedUser = userRepository.save(user);
        boolean profileUpdated = syncProfile(savedUser, existingProfile, syncSnapshot, email.pending(), now);
        evictUserCaches(savedUser);

        return new BridgeUserMirrorSyncResult(
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

    /**
     * PR-27: where Contexa owns the sign-in the user signed in with one of Contexa's accounts, which is the record of the
     * user. A copy made a second row of the same person. Where the application owns the sign-in a name says nothing: the
     * application's user is matched to its copy only, never to a Contexa account of the same name.
     */
    private Optional<Long> ownAccount(String subject) {
        return bridgeProperties.ownershipBehaviour() == OwnershipBehaviour.CONTEXA_OWNED
                ? userRepository.findOwnAccountId(subject)
                : Optional.empty();
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
        if (hasUserFieldChanges(existingUser, existingProfile, authenticationStamp, requestContext, bridgeSubjectKey, externalSubjectId, authenticationSource, organizationId)) {
            return false;
        }
        return true;
    }

    private boolean hasUserFieldChanges(
            Users user,
            BridgeUserProfile profile,
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
        if (wouldChangeString(user.getPrincipalType(), fit(normalize(authenticationStamp.principalType()), PRINCIPAL_TYPE_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getOrganizationId(), organizationId)) {
            return true;
        }
        EmailChange email = resolveEmail(user, profile, authenticationStamp, bridgeSubjectKey);
        if (wouldChangeString(user.getEmail(), email.email())
                || !Objects.equals(normalize(profile.getPendingEmail()), email.pending())) {
            return true;
        }
        if (wouldChangeString(user.getName(), fit(firstText(authenticationStamp.displayName(), externalSubjectId), TEXT_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getPhone(), fit(attribute(authenticationStamp.attributes(), "phone", "mobile", "mobileNumber"), PHONE_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getDepartment(), fit(attribute(authenticationStamp.attributes(), "department", "team", "division"), TEXT_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getPosition(), fit(attribute(authenticationStamp.attributes(), "position", "jobTitle", "title"), TEXT_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getProfileImageUrl(), fit(attribute(authenticationStamp.attributes(), "profileImageUrl", "profile_image_url", "avatarUrl"), PROFILE_IMAGE_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getLocale(), fit(attribute(authenticationStamp.attributes(), "locale", "language", "lang"), LOCALE_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getTimezone(), fit(attribute(authenticationStamp.attributes(), "timezone", "timeZone"), TIMEZONE_MAX))) {
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
            EmailChange email,
            LocalDateTime now
    ) {
        boolean changed = false;
        if (user.getUsername() == null || user.getUsername().isBlank()) {
            user.setUsername(bridgeSubjectKey);
            changed = true;
        }
        if (user.getPassword() == null || user.getPassword().isBlank()) {
            user.setPassword("{bcrypt}" + SHADOW_PASSWORD_ENCODER.encode(UUID.randomUUID().toString()));
            changed = true;
        }

        changed |= setIfChanged(user.getEmail(), email.email(), user::setEmail);
        changed |= setIfChanged(user.getName(), fit(firstText(authenticationStamp.displayName(), externalSubjectId), TEXT_MAX), user::setName);
        changed |= setIfChanged(user.getPhone(), fit(attribute(authenticationStamp.attributes(), "phone", "mobile", "mobileNumber"), PHONE_MAX), user::setPhone);
        changed |= setIfChanged(user.getDepartment(), fit(attribute(authenticationStamp.attributes(), "department", "team", "division"), TEXT_MAX), user::setDepartment);
        changed |= setIfChanged(user.getPosition(), fit(attribute(authenticationStamp.attributes(), "position", "jobTitle", "title"), TEXT_MAX), user::setPosition);
        changed |= setIfChanged(user.getProfileImageUrl(), fit(attribute(authenticationStamp.attributes(), "profileImageUrl", "profile_image_url", "avatarUrl"), PROFILE_IMAGE_MAX), user::setProfileImageUrl);
        changed |= setIfChanged(user.getLocale(), fit(attribute(authenticationStamp.attributes(), "locale", "language", "lang"), LOCALE_MAX), user::setLocale);
        changed |= setIfChanged(user.getTimezone(), fit(attribute(authenticationStamp.attributes(), "timezone", "timeZone"), TIMEZONE_MAX), user::setTimezone);
        changed |= setIfChanged(user.getExternalSubjectId(), externalSubjectId, user::setExternalSubjectId);
        changed |= setIfChanged(user.getAuthenticationSource(), authenticationSource, user::setAuthenticationSource);
        changed |= setIfChanged(user.getPrincipalType(), fit(normalize(authenticationStamp.principalType()), PRINCIPAL_TYPE_MAX), user::setPrincipalType);
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
            @Nullable String pendingEmail,
            LocalDateTime now
    ) {
        BridgeUserProfile profile = existingProfile != null
                ? existingProfile
                // A new profile keeps a null id so that JPA persists it; @MapsId derives the id from the user.
                : BridgeUserProfile.builder().user(user).build();

        boolean changed = false;
        changed |= setIfChanged(profile.getSourceSystem(), syncSnapshot.sourceSystem(), profile::setSourceSystem);
        changed |= setIfChanged(profile.getAuthenticationType(), syncSnapshot.authenticationType(), profile::setAuthenticationType);
        changed |= setIfChanged(profile.getAuthenticationAssurance(), syncSnapshot.authenticationAssurance(), profile::setAuthenticationAssurance);
        changed |= setIfChanged(profile.getMfaCompletedFromCustomer(), syncSnapshot.mfaCompletedFromCustomer(), profile::setMfaCompletedFromCustomer);
        changed |= setIfChanged(profile.getSessionId(), syncSnapshot.sessionId(), profile::setSessionId);
        changed |= setIfChanged(profile.getLastAuthoritiesJson(), syncSnapshot.authoritiesJson(), profile::setLastAuthoritiesJson);
        changed |= setIfChanged(profile.getLastAttributesJson(), syncSnapshot.attributesJson(), profile::setLastAttributesJson);
        changed |= setIfChanged(profile.getLastSyncHash(), syncSnapshot.syncHash(), profile::setLastSyncHash);
        if (!Objects.equals(profile.getPendingEmail(), pendingEmail)) {
            if (pendingEmail != null) {
                log.warn("[Bridge] The application shows another address for a user whose copy has one; it waits until "
                        + "the user proves the address on record: userId={}", user.getId());
            }
            profile.setPendingEmail(pendingEmail);
            changed = true;
        }

        if (!now.equals(profile.getLastSyncedAt())) {
            profile.setLastSyncedAt(now);
            changed = true;
        }

        if (changed || profile.getUser() == null) {
            profile.setUser(user);
            bridgeUserProfileRepository.save(profile);
            return true;
        }
        return false;
    }

    /**
     * The copy's address and the one waiting for the user. The step-up mails its codes to the copy's address, and
     * whoever holds a session can change the application's profile. So the first real address the application shows
     * goes in at once, and once the copy holds one, another address the application shows waits until the user proves
     * the address on record ({@link #confirmPendingEmail(Long)}) or an administrator enters an address.
     */
    private EmailChange resolveEmail(Users user, @Nullable BridgeUserProfile profile,
                                     AuthenticationStamp authenticationStamp, String bridgeSubjectKey) {
        String current = normalize(user.getEmail());
        String waiting = profile != null ? normalize(profile.getPendingEmail()) : null;
        String shown = applicationEmail(user, authenticationStamp, bridgeSubjectKey);
        if (shown == null) {
            return new EmailChange(firstText(current, syntheticEmail(bridgeSubjectKey)), waiting);
        }
        if (!isRealAddress(current)) {
            return new EmailChange(shown, null);
        }
        if (shown.equalsIgnoreCase(current)) {
            return new EmailChange(current, null);
        }
        return new EmailChange(current, shown);
    }

    /** The address the application shows for the user now, or null for none that fits the column. */
    @Nullable
    private String applicationEmail(Users user, AuthenticationStamp authenticationStamp, String bridgeSubjectKey) {
        String email = normalize(attribute(authenticationStamp.attributes(), "email", "mail", "userEmail"));
        if (email == null) {
            email = providedEmail(user, authenticationStamp, bridgeSubjectKey);
        }
        if (email == null || email.length() > LONG_TEXT_MAX) {
            return null;
        }
        return email.toLowerCase(Locale.ROOT);
    }

    /** An address a code can go to: not none, and not the one made up for a user who showed none. */
    private boolean isRealAddress(@Nullable String address) {
        String domain = bridgeProperties.getSync().getSyntheticEmailDomain();
        return address != null && address.contains("@")
                && (domain == null || !address.toLowerCase(Locale.ROOT).endsWith("@" + domain.toLowerCase(Locale.ROOT)));
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public boolean confirmPendingEmail(Long userId) {
        if (userId == null) {
            return false;
        }
        BridgeUserProfile profile = bridgeUserProfileRepository.findById(userId).orElse(null);
        String waiting = profile != null ? normalize(profile.getPendingEmail()) : null;
        if (waiting == null) {
            return false;
        }
        Users user = userRepository.findById(userId).filter(Users::isBridgeManaged).orElse(null);
        if (user == null) {
            return false;
        }
        Optional<Users> holder = userRepository.findFirstByEmailIgnoreCase(waiting);
        if (holder.isPresent() && !userId.equals(holder.get().getId())) {
            log.warn("[Bridge] The address waiting for a user is another user's; the copy keeps the address on record: "
                    + "userId={}", userId);
            return false;
        }
        user.setEmail(waiting);
        profile.setPendingEmail(null);
        userRepository.save(user);
        bridgeUserProfileRepository.save(profile);
        evictUserCaches(user);
        log.info("[Bridge] The user proved the address on record; the copy takes the address the application shows: "
                + "userId={}", userId);
        return true;
    }

    /**
     * Q-1: the address the application tells, asked only while the copy has no real one: an address an administrator
     * entered stands. An application that fails to answer stops nothing.
     */
    private String providedEmail(Users user, AuthenticationStamp authenticationStamp, String bridgeSubjectKey) {
        String current = normalize(user.getEmail());
        if (emailProvider == null || (current != null && !current.equals(syntheticEmail(bridgeSubjectKey)))) {
            return null;
        }
        try {
            return normalize(emailProvider.emailOf(authenticationStamp.principalId()));
        } catch (RuntimeException e) {
            log.error("[Bridge] The application's BridgeUserEmailProvider failed: {}", e.toString());
            return null;
        }
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

    /** The value cut to the length of its column (META-INF/contexa/db/schema.sql, users), so that one long value of the host cannot fail the copy. */
    private static String fit(@Nullable String value, int max) {
        if (value == null || value.length() <= max) {
            return value;
        }
        return value.substring(0, max).trim();
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
            log.error("[Bridge] Failed to serialize bridge user mirror payload", ex);
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
                builder.append(String.format(Locale.ROOT, "%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm is unavailable", ex);
        }
    }

    /** The copy's address, and the address that waits for the user to prove the one on record (null for none). */
    private record EmailChange(String email, @Nullable String pending) {
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


