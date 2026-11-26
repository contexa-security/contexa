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
import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexacommon.entity.UserRole;
import io.contexa.contexacommon.entity.UserRolePermission;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.operating.OperatingBehaviour;
import io.contexa.contexacommon.repository.BridgeUserProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.UserRolePermissionRepository;
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
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

/**
 * The copy Contexa keeps of an application's user (bridge v2, B5-1). It keeps the values {@link BridgeUserCopyFacts} lists
 * and is written only when one of them changes; a sign-in also writes when and from where the user signed in. It never
 * makes up an address, never turns a copy an administrator turned off back on, and keeps neither the session nor the
 * application's attributes. The copy is found by the user's decision key, the key Contexa's decisions about the user
 * are kept under.
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultBridgeUserMirrorSyncService implements BridgeUserMirrorSyncService {

    /**
     * The password a copy of the application's user carries so that the record is complete. Nobody knows what it was made
     * from (a random value, never kept), so no one signs in with it, and one such hash does for every copy: hashing a
     * value of its own for each new user cost 60 to 100 ms of processor each, and with a thousand people signing in at once
     * that was most of what the server did (a flight recording of the load test: 86 % of the samples). It is made when the
     * first copy needs it.
     */
    private static final class ShadowPassword {
        private static final String VALUE = "{bcrypt}" + new BCryptPasswordEncoder().encode(UUID.randomUUID().toString());
    }

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
    private final Set<String> keptApart = ConcurrentHashMap.newKeySet();
    private BridgeUserEmailProvider emailProvider;
    @Nullable
    private UserRolePermissionRepository rolePermissions;
    private List<UserCopyMergeContributor> mergeContributors = List.of();
    @Nullable
    private BooleanSupplier applicationsUsersAreContexaAccounts;
    private UnaryOperator<String> userKey = UnaryOperator.identity();

    /** Q-1: where the application tells the address of a user who carries none. */
    public void setEmailProvider(BridgeUserEmailProvider emailProvider) {
        this.emailProvider = emailProvider;
    }

    /**
     * Whether the application's users sign in as Contexa's own accounts, as the running application tells it: Contexa's main
     * chain signs them in (FULL) from Contexa's own store, which is so with CONTEXA_OWNED, and with HOST_OWNED only while
     * the application has no store of its own. Without it the way of running answers alone: FULL with CONTEXA_OWNED.
     */
    public void setApplicationsUsersAreContexaAccounts(BooleanSupplier applicationsUsersAreContexaAccounts) {
        this.applicationsUsersAreContexaAccounts = applicationsUsersAreContexaAccounts;
    }

    /**
     * The decision key of a user id (decision 7 of the bridge v2 standard): the key Contexa's decisions about the user are
     * kept under, so that the copy, the step-up and the decisions name one user the same way. Without it a user id is its
     * own key.
     */
    public void setUserKey(UnaryOperator<String> userKey) {
        this.userKey = userKey != null ? userKey : UnaryOperator.identity();
    }

    /** bridge v2 B5-3: the grants a merged copy holds, which go to the copy of the same person it is merged into. */
    public void setRolePermissions(@Nullable UserRolePermissionRepository rolePermissions) {
        this.rolePermissions = rolePermissions;
    }

    /** bridge v2 B5-3: the modules that keep a state under a copy's name, asked when two copies of a person become one. */
    public void setMergeContributors(@Nullable List<UserCopyMergeContributor> mergeContributors) {
        this.mergeContributors = mergeContributors != null ? List.copyOf(mergeContributors) : List.of();
    }

    @Override
    public BridgeUserMirrorSyncResult sync(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            RequestContextSnapshot requestContext
    ) {
        return sync(authenticationStamp, authorizationStamp, requestContext, false);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public BridgeUserMirrorSyncResult sync(
            AuthenticationStamp authenticationStamp,
            AuthorizationStamp authorizationStamp,
            RequestContextSnapshot requestContext,
            boolean signIn
    ) {
        if (!bridgeProperties.getSync().isEnabled() || authenticationStamp == null || !authenticationStamp.authenticated()) {
            return null;
        }

        String givenSubjectId = normalize(authenticationStamp.principalId());
        if (givenSubjectId == null) {
            return null;
        }
        if (givenSubjectId.length() > LONG_TEXT_MAX) {
            // The subject is the key the copy is found by: cut, it would be another user's. No copy is made (the
            // user has no step-up factor of its own then); said once, not on every request.
            if (tooLongSubjects.size() < 1000 && tooLongSubjects.add(Integer.toHexString(givenSubjectId.hashCode()))) {
                log.error("[Bridge] No user copy for a subject longer than {} characters ({} characters)", LONG_TEXT_MAX,
                        givenSubjectId.length());
            }
            return null;
        }

        Optional<Long> ownAccount = ownAccount(givenSubjectId);
        if (ownAccount.isPresent()) {
            return new BridgeUserMirrorSyncResult(ownAccount.get(), givenSubjectId, givenSubjectId, null, false, false, false, false);
        }

        String externalSubjectId = decisionKey(givenSubjectId);
        String authenticationSource = fit(firstText(
                authenticationStamp.authenticationSource(),
                BridgeUserCopyFacts.attribute(authenticationStamp.attributes(), "authenticationSource", "authSource", "sourceSystem"),
                "BRIDGE"
        ), TEXT_MAX);
        String organizationId = fit(BridgeUserCopyFacts.attribute(authenticationStamp.attributes(),
                BridgeUserCopyFacts.ORGANIZATION), LONG_TEXT_MAX);
        String bridgeSubjectKey = generateBridgeSubjectKey(organizationId, externalSubjectId);
        String keyOfTheGivenId = givenSubjectId.equals(externalSubjectId)
                ? null : generateBridgeSubjectKey(organizationId, givenSubjectId);
        LocalDateTime now = LocalDateTime.now();

        Optional<Users> existingUser = resolveUser(bridgeSubjectKey, keyOfTheGivenId, externalSubjectId, givenSubjectId,
                organizationId);
        String copyKey = bridgeSubjectKey;
        if (existingUser.isPresent() && !bridgeSubjectKey.equals(existingUser.get().getBridgeSubjectKey())
                && !mergeTheOtherCopies(existingUser.get(), externalSubjectId, givenSubjectId, organizationId)) {
            copyKey = existingUser.get().getBridgeSubjectKey();
        }
        BridgeUserProfile existingProfile = existingUser
                .flatMap(user -> user.getId() != null ? bridgeUserProfileRepository.findById(user.getId()) : Optional.empty())
                .orElse(null);

        SyncSnapshot syncSnapshot = buildSyncSnapshot(authenticationStamp);
        if (shouldSkipSync(existingUser.orElse(null), existingProfile, authenticationStamp, requestContext, syncSnapshot,
                copyKey, externalSubjectId, givenSubjectId, authenticationSource, organizationId, signIn)) {
            Users user = existingUser.orElseThrow();
            return new BridgeUserMirrorSyncResult(
                    user.getId(),
                    user.getUsername(),
                    externalSubjectId,
                    copyKey,
                    user.isBridgeManaged(),
                    user.isExternalAuthOnly(),
                    false,
                    false
            );
        }

        Users user = existingUser.orElseGet(Users::new);
        boolean created = user.getId() == null;
        EmailChange email = resolveEmail(user, existingProfile, authenticationStamp);
        boolean updated = applyUser(user, authenticationStamp, requestContext, copyKey, externalSubjectId,
                givenSubjectId, authenticationSource, organizationId, email, now, created || signIn);

        Users savedUser = userRepository.save(user);
        boolean profileUpdated = syncProfile(savedUser, existingProfile, syncSnapshot, email.pending(), now);
        evictUserCaches(savedUser);

        return new BridgeUserMirrorSyncResult(
                savedUser.getId(),
                savedUser.getUsername(),
                externalSubjectId,
                copyKey,
                savedUser.isBridgeManaged(),
                savedUser.isExternalAuthOnly(),
                created,
                updated || profileUpdated
        );
    }

    /** The decision key of the given user id, never longer than its column; the given id when the key would be. */
    private String decisionKey(String givenSubjectId) {
        String key = normalize(userKey.apply(givenSubjectId));
        return key != null && key.length() <= LONG_TEXT_MAX ? key : givenSubjectId;
    }

    /**
     * PR-27: where the application's users sign in as Contexa's accounts, the user signed in with one of them, which is
     * the record of the user; a copy made a second row of the same person. Elsewhere a name says nothing: the
     * application's user is matched to its copy only, never to a Contexa account of the same name. That is so where the
     * application signs its users in (SANDBOX), and where Contexa's main chain signs them in from the application's own
     * store (FULL with HOST_OWNED, R-17).
     */
    private Optional<Long> ownAccount(String subject) {
        return applicationsUsersAreContexaAccounts()
                ? userRepository.findOwnAccountId(subject)
                : Optional.empty();
    }

    private boolean applicationsUsersAreContexaAccounts() {
        if (applicationsUsersAreContexaAccounts != null) {
            return applicationsUsersAreContexaAccounts.getAsBoolean();
        }
        OperatingBehaviour behaviour = bridgeProperties.operatingBehaviour();
        return behaviour.signsInTheApplicationsUsers() && !behaviour.hostComponentsWin();
    }

    /**
     * The copy of the person: the one under the key, else the one kept under the key of the id as the application gave
     * it (a copy made before copies were keyed by the decision key), else the one a synchronisation made before the key
     * left out the way the person was read (the security context, an explicit handoff, the session). A person those
     * older synchronisations split into a copy per way or per spelling of the id finds the first of them, so no further
     * copy is made, and the copies made after it are merged into it ({@link #mergeTheOtherCopies}).
     */
    private Optional<Users> resolveUser(
            String bridgeSubjectKey,
            @Nullable String keyOfTheGivenId,
            String externalSubjectId,
            String givenSubjectId,
            @Nullable String organizationId
    ) {
        Optional<Users> byBridgeSubjectKey = userRepository.findByBridgeSubjectKey(bridgeSubjectKey);
        if (byBridgeSubjectKey.isPresent()) {
            return byBridgeSubjectKey;
        }
        if (keyOfTheGivenId != null) {
            Optional<Users> byKeyOfTheGivenId = userRepository.findByBridgeSubjectKey(keyOfTheGivenId);
            if (byKeyOfTheGivenId.isPresent()) {
                return byKeyOfTheGivenId;
            }
        }
        Optional<Users> byDecisionKey = firstCopyOf(externalSubjectId, organizationId);
        if (byDecisionKey.isPresent() || givenSubjectId.equals(externalSubjectId)) {
            return byDecisionKey;
        }
        return firstCopyOf(givenSubjectId, organizationId);
    }

    private Optional<Users> firstCopyOf(String externalSubjectId, @Nullable String organizationId) {
        return copiesOf(externalSubjectId, organizationId).stream()
                .min(Comparator.comparing(Users::getId, Comparator.nullsLast(Comparator.naturalOrder())));
    }

    private List<Users> copiesOf(String externalSubjectId, @Nullable String organizationId) {
        return userRepository.findByExternalSubjectIdAndBridgeManagedTrue(externalSubjectId).stream()
                .filter(copy -> Objects.equals(normalize(copy.getOrganizationId()), organizationId))
                .toList();
    }

    /**
     * bridge v2 B5-3: the other copies of the person, which older versions made per way the person was read or per
     * spelling of the id, become the kept copy in this transaction, found as {@link #resolveUser} finds the kept one: under
     * the decision key and under the id as given, in the same organization. A copy a contributor refuses to merge stays,
     * and the kept copy keeps its key until then, so a later synchronisation tries again.
     *
     * @return whether every other copy of the person was merged
     */
    private boolean mergeTheOtherCopies(Users kept, String externalSubjectId, String givenSubjectId,
                                        @Nullable String organizationId) {
        Map<Long, Users> others = new LinkedHashMap<>();
        copiesOf(externalSubjectId, organizationId).forEach(copy -> others.putIfAbsent(copy.getId(), copy));
        if (!givenSubjectId.equals(externalSubjectId)) {
            copiesOf(givenSubjectId, organizationId).forEach(copy -> others.putIfAbsent(copy.getId(), copy));
        }
        others.remove(kept.getId());
        boolean merged = true;
        for (Users other : others.values()) {
            String refusal = mergeRefusal(kept, other);
            if (refusal != null) {
                merged = false;
                if (keptApart.size() < 1000 && keptApart.add(externalSubjectId)) {
                    log.error("[Bridge] Two copies of one user are kept apart ({}); a later synchronisation merges them "
                            + "once that is resolved: userId={}", refusal, kept.getId());
                }
                continue;
            }
            mergeInto(kept, other);
        }
        return merged;
    }

    @Nullable
    private String mergeRefusal(Users kept, Users other) {
        for (UserCopyMergeContributor contributor : mergeContributors) {
            String refusal = contributor.refusal(kept.getUsername(), other.getUsername());
            if (refusal != null) {
                return refusal;
            }
        }
        return null;
    }

    /**
     * The other copy's groups, roles and grants become the kept copy's (one of each, as their keys allow), a copy an
     * administrator turned off or locked keeps the person off or locked, the contributors move their own states, and the
     * other copy goes with its profile.
     */
    private void mergeInto(Users kept, Users other) {
        Set<Long> groups = new HashSet<>();
        kept.getUserGroups().forEach(link -> groups.add(link.getGroup().getId()));
        for (UserGroup link : other.getUserGroups()) {
            if (groups.add(link.getGroup().getId())) {
                kept.getUserGroups().add(UserGroup.builder().user(kept).group(link.getGroup())
                        .assignedAt(link.getAssignedAt()).assignedBy(link.getAssignedBy()).build());
            }
        }
        Set<Long> roles = new HashSet<>();
        kept.getUserRoles().forEach(link -> roles.add(link.getRole().getId()));
        for (UserRole link : other.getUserRoles()) {
            if (roles.add(link.getRole().getId())) {
                kept.getUserRoles().add(UserRole.builder().user(kept).role(link.getRole())
                        .assignedAt(link.getAssignedAt()).assignedBy(link.getAssignedBy()).build());
            }
        }
        if (rolePermissions != null) {
            Set<List<Long>> grants = new HashSet<>();
            rolePermissions.findByUserId(kept.getId())
                    .forEach(grant -> grants.add(List.of(grant.getRole().getId(), grant.getPermission().getId())));
            List<UserRolePermission> moved = rolePermissions.findByUserId(other.getId());
            for (UserRolePermission grant : moved) {
                if (grants.add(List.of(grant.getRole().getId(), grant.getPermission().getId()))) {
                    rolePermissions.save(new UserRolePermission(kept, grant.getRole(), grant.getPermission(),
                            grant.getAssignedAt(), grant.getAssignedBy()));
                }
            }
            rolePermissions.deleteAll(moved);
        }
        kept.setEnabled(kept.isEnabled() && other.isEnabled());
        kept.setAccountLocked(kept.isAccountLocked() || other.isAccountLocked());
        for (UserCopyMergeContributor contributor : mergeContributors) {
            contributor.merge(kept.getUsername(), other.getUsername());
        }
        if (bridgeUserProfileRepository.existsById(other.getId())) {
            bridgeUserProfileRepository.deleteById(other.getId());
        }
        userRepository.save(kept);
        userRepository.delete(other);
        evictUserCaches(kept);
        evictUserCaches(other);
    }

    /**
     * Whether the copy already holds everything: no value it keeps changed, nothing it no longer keeps is left in it, and
     * a sign-in finds the same time and address of the last sign-in. Neither the request's address nor a refreshed token
     * writes the copy, and an unchanged copy is not rewritten after a while.
     */
    private boolean shouldSkipSync(
            @Nullable Users existingUser,
            @Nullable BridgeUserProfile existingProfile,
            AuthenticationStamp authenticationStamp,
            RequestContextSnapshot requestContext,
            SyncSnapshot syncSnapshot,
            String bridgeSubjectKey,
            String externalSubjectId,
            String givenSubjectId,
            String authenticationSource,
            String organizationId,
            boolean signIn
    ) {
        if (existingUser == null || existingProfile == null) {
            return false;
        }
        if (!syncSnapshot.syncHash().equals(existingProfile.getLastSyncHash())) {
            return false;
        }
        if (existingProfile.getSessionId() != null || existingProfile.getLastAttributesJson() != null) {
            return false;
        }
        if (signIn && lastSignInChanges(existingUser, authenticationStamp, requestContext)) {
            return false;
        }
        return !hasUserFieldChanges(existingUser, existingProfile, authenticationStamp, bridgeSubjectKey,
                externalSubjectId, givenSubjectId, authenticationSource, organizationId);
    }

    private boolean lastSignInChanges(Users user, AuthenticationStamp authenticationStamp,
                                      @Nullable RequestContextSnapshot requestContext) {
        LocalDateTime lastLoginAt = lastLoginAt(authenticationStamp, requestContext);
        String lastLoginIp = requestContext != null ? normalize(requestContext.clientIp()) : null;
        return (lastLoginAt != null && !lastLoginAt.equals(user.getLastLoginAt()))
                || wouldChangeString(user.getLastLoginIp(), lastLoginIp);
    }

    private boolean hasUserFieldChanges(
            Users user,
            BridgeUserProfile profile,
            AuthenticationStamp authenticationStamp,
            String bridgeSubjectKey,
            String externalSubjectId,
            String givenSubjectId,
            String authenticationSource,
            String organizationId
    ) {
        Map<String, Object> attributes = authenticationStamp.attributes();
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
        EmailChange email = resolveEmail(user, profile, authenticationStamp);
        if (!Objects.equals(normalize(user.getEmail()), email.email())
                || !Objects.equals(normalize(profile.getPendingEmail()), email.pending())) {
            return true;
        }
        if (wouldChangeString(user.getName(), fit(firstText(authenticationStamp.displayName(), givenSubjectId), TEXT_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getPhone(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.PHONE), PHONE_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getDepartment(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.DEPARTMENT), TEXT_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getPosition(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.POSITION), TEXT_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getProfileImageUrl(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.PROFILE_IMAGE), PROFILE_IMAGE_MAX))) {
            return true;
        }
        if (wouldChangeString(user.getLocale(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.LOCALE), LOCALE_MAX))) {
            return true;
        }
        return wouldChangeString(user.getTimezone(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.TIMEZONE), TIMEZONE_MAX));
    }

    /**
     * Writes the values the copy keeps. Whether the copy is turned on is left as it is: a new copy is on, and a copy an
     * administrator turned off stays off. When and from where the user signed in is written by a sign-in and when the
     * copy is made, never by any other request.
     */
    private boolean applyUser(
            Users user,
            AuthenticationStamp authenticationStamp,
            RequestContextSnapshot requestContext,
            String bridgeSubjectKey,
            String externalSubjectId,
            String givenSubjectId,
            String authenticationSource,
            String organizationId,
            EmailChange email,
            LocalDateTime now,
            boolean writeTheSignIn
    ) {
        Map<String, Object> attributes = authenticationStamp.attributes();
        boolean changed = false;
        if (user.getUsername() == null || user.getUsername().isBlank()) {
            user.setUsername(bridgeSubjectKey);
            changed = true;
        }
        if (user.getPassword() == null || user.getPassword().isBlank()) {
            user.setPassword(ShadowPassword.VALUE);
            changed = true;
        }

        if (!Objects.equals(user.getEmail(), email.email())) {
            user.setEmail(email.email());
            changed = true;
        }
        changed |= setIfChanged(user.getName(), fit(firstText(authenticationStamp.displayName(), givenSubjectId), TEXT_MAX), user::setName);
        changed |= setIfChanged(user.getPhone(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.PHONE), PHONE_MAX), user::setPhone);
        changed |= setIfChanged(user.getDepartment(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.DEPARTMENT), TEXT_MAX), user::setDepartment);
        changed |= setIfChanged(user.getPosition(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.POSITION), TEXT_MAX), user::setPosition);
        changed |= setIfChanged(user.getProfileImageUrl(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.PROFILE_IMAGE), PROFILE_IMAGE_MAX), user::setProfileImageUrl);
        changed |= setIfChanged(user.getLocale(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.LOCALE), LOCALE_MAX), user::setLocale);
        changed |= setIfChanged(user.getTimezone(), fit(BridgeUserCopyFacts.attribute(attributes, BridgeUserCopyFacts.TIMEZONE), TIMEZONE_MAX), user::setTimezone);
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

        if (writeTheSignIn) {
            LocalDateTime lastLoginAt = lastLoginAt(authenticationStamp, requestContext);
            if (lastLoginAt != null && !lastLoginAt.equals(user.getLastLoginAt())) {
                user.setLastLoginAt(lastLoginAt);
                changed = true;
            }
            String lastLoginIp = requestContext != null ? normalize(requestContext.clientIp()) : null;
            changed |= setIfChanged(user.getLastLoginIp(), lastLoginIp, user::setLastLoginIp);
        }

        if (!now.equals(user.getLastBridgedAt())) {
            user.setLastBridgedAt(now);
            changed = true;
        }
        return changed;
    }

    @Nullable
    private LocalDateTime lastLoginAt(AuthenticationStamp authenticationStamp, @Nullable RequestContextSnapshot requestContext) {
        return toLocalDateTime(firstInstant(authenticationStamp.authenticationTime(),
                requestContext != null ? requestContext.collectedAt() : null));
    }

    /**
     * The profile values of the copy and the hash of everything the copy keeps ({@link BridgeUserCopyFacts}). The
     * authorities are the application's own; what an authorization made of them is not kept.
     */
    private SyncSnapshot buildSyncSnapshot(AuthenticationStamp authenticationStamp) {
        return new SyncSnapshot(
                normalize(authenticationStamp.authenticationSource()),
                normalize(authenticationStamp.authenticationType()),
                normalize(authenticationStamp.authenticationAssurance()),
                authenticationStamp.mfaCompleted(),
                toJson(BridgeUserCopyFacts.authorities(authenticationStamp.authorities())),
                hash(toJson(BridgeUserCopyFacts.of(authenticationStamp)))
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
        changed |= setIfChanged(profile.getLastAuthoritiesJson(), syncSnapshot.authoritiesJson(), profile::setLastAuthoritiesJson);
        changed |= setIfChanged(profile.getLastSyncHash(), syncSnapshot.syncHash(), profile::setLastSyncHash);
        if (profile.getSessionId() != null || profile.getLastAttributesJson() != null) {
            profile.setSessionId(null);
            profile.setLastAttributesJson(null);
            changed = true;
        }
        if (!Objects.equals(profile.getPendingEmail(), pendingEmail)) {
            if (pendingEmail != null) {
                log.error("[Bridge] The application shows another address for a user whose copy has one; it waits until "
                        + "the user proves the address on record and then this address: userId={}", user.getId());
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
     * the address on record and then that address ({@link #confirmPendingEmail(Long, String)}), or an administrator
     * enters an address. No address is made up for a user the application shows none for: the copy keeps a real address
     * it has, and none otherwise (one made up by an older version goes).
     */
    private EmailChange resolveEmail(Users user, @Nullable BridgeUserProfile profile,
                                     AuthenticationStamp authenticationStamp) {
        String current = normalize(user.getEmail());
        String waiting = profile != null ? normalize(profile.getPendingEmail()) : null;
        String shown = applicationEmail(user, authenticationStamp);
        if (shown == null) {
            return new EmailChange(isRealAddress(current) ? current : null, waiting);
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
    private String applicationEmail(Users user, AuthenticationStamp authenticationStamp) {
        String email = normalize(BridgeUserCopyFacts.attribute(authenticationStamp.attributes(), BridgeUserCopyFacts.EMAIL));
        if (email == null) {
            email = providedEmail(user, authenticationStamp);
        }
        if (email == null || email.length() > LONG_TEXT_MAX) {
            return null;
        }
        return email.toLowerCase(Locale.ROOT);
    }

    /**
     * An address a code can go to: not none, and not one an older version made up for a user who showed none (those end
     * in {@code contexa.bridge.sync.synthetic-email-domain}).
     */
    private boolean isRealAddress(@Nullable String address) {
        String domain = bridgeProperties.getSync().getSyntheticEmailDomain();
        return address != null && address.contains("@")
                && (domain == null || !address.toLowerCase(Locale.ROOT).endsWith("@" + domain.toLowerCase(Locale.ROOT)));
    }

    @Override
    @Nullable
    @Transactional(transactionManager = "contexaTransactionManager")
    public String pendingEmail(Long userId) {
        if (userId == null) {
            return null;
        }
        return bridgeUserProfileRepository.findById(userId).map(BridgeUserProfile::getPendingEmail)
                .map(this::normalize).orElse(null);
    }

    /**
     * The address waiting becomes the copy's. Copies may share an address (decision 5: the step-up then mails no code to
     * any of them); only an address one of Contexa's own accounts has is never taken, since accounts are told apart by it.
     */
    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public boolean confirmPendingEmail(Long userId, String address) {
        String proven = normalize(address);
        if (userId == null || proven == null) {
            return false;
        }
        BridgeUserProfile profile = bridgeUserProfileRepository.findById(userId).orElse(null);
        String waiting = profile != null ? normalize(profile.getPendingEmail()) : null;
        if (waiting == null) {
            return false;
        }
        if (!waiting.equalsIgnoreCase(proven)) {
            log.error("[Bridge] The address the user proved no longer waits; the copy keeps the address on record: "
                    + "userId={}", userId);
            return false;
        }
        Users user = userRepository.findById(userId).filter(Users::isBridgeManaged).orElse(null);
        if (user == null) {
            return false;
        }
        Optional<Users> account = userRepository.findFirstByEmailIgnoreCaseAndBridgeManagedFalse(waiting);
        if (account.isPresent() && !userId.equals(account.get().getId())) {
            log.error("[Bridge] The address waiting for a user is one of Contexa's accounts; the copy keeps the address on "
                    + "record: userId={}", userId);
            return false;
        }
        user.setEmail(waiting);
        profile.setPendingEmail(null);
        userRepository.save(user);
        bridgeUserProfileRepository.save(profile);
        evictUserCaches(user);
        return true;
    }

    /**
     * Q-1: the address the application tells, asked only while the copy has no real one: an address an administrator
     * entered stands. An application that fails to answer stops nothing.
     */
    private String providedEmail(Users user, AuthenticationStamp authenticationStamp) {
        String current = normalize(user.getEmail());
        if (emailProvider == null || isRealAddress(current)) {
            return null;
        }
        try {
            return normalize(emailProvider.emailOf(authenticationStamp.principalId()));
        } catch (RuntimeException e) {
            log.error("[Bridge] The application's BridgeUserEmailProvider failed: {}", e.toString());
            return null;
        }
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

    /**
     * The key of the copy: the person's decision key within its organization. The way the bridge read the person (the
     * security context, an explicit handoff, the session) is not part of it: with it, one person became a copy per way,
     * and the step-up offers no factor to a person with more than one copy. The canonical text is prefixed, so it is not
     * the text of a key that named one of the bridge's ways.
     */
    private String generateBridgeSubjectKey(String organizationId, String externalSubjectId) {
        String canonical = String.join("|",
                "SUBJECT",
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
    private record EmailChange(@Nullable String email, @Nullable String pending) {
    }

    private record SyncSnapshot(
            String sourceSystem,
            String authenticationType,
            String authenticationAssurance,
            Boolean mfaCompletedFromCustomer,
            String authoritiesJson,
            String syncHash
    ) {
    }
}
