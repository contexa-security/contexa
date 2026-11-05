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
package io.contexa.contexacore.security.zerotrust;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.store.ExpiringStateStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.AISecurityContextSupport;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Slf4j
public abstract class AbstractZeroTrustSecurityService implements ZeroTrustSecurityService, ExpiringStateStore {

    private static final String ZERO_TRUST_ACTION_ATTR = "contexa.zeroTrustAction";

    protected final ThreatScoreUtil threatScoreUtil;
    protected final SecurityZeroTrustProperties securityZeroTrustProperties;
    protected final ZeroTrustActionRepository actionRepository;
    protected BlockingSignalBroadcaster blockingSignalBroadcaster;

    private final Cache<String, CachedZeroTrustDecision> decisionCache;
    /**
     * The identifiers registered since the last sweep, each with the deadline it was registered with
     * ({@link #UNTIMED} for none). A request writes only when its identifier is not here or the recorded deadline no
     * longer covers what the request shows; the sweep clears it, so every live identifier registers once more.
     */
    private final Map<String, Instant> registeredSessions = new ConcurrentHashMap<>();
    private static final Instant UNTIMED = Instant.MAX;
    /** Added to every deadline: clocks of the nodes and of the token issuer differ, and containers expire lazily. */
    private static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

    protected AbstractZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository) {
        this.threatScoreUtil = threatScoreUtil;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
        this.actionRepository = actionRepository;
        this.decisionCache = Caffeine.newBuilder()
                .maximumSize(10000)
                .expireAfterWrite(5, TimeUnit.SECONDS)
                .build();
    }

    @Override
    public void applyZeroTrustToContext(SecurityContext context, String userId, String sessionId, HttpServletRequest request) {
        if (!securityZeroTrustProperties.isEnabled() || context == null || userId == null) {
            return;
        }
        try {
            // The context is loading here: its own authentication names the binding (reading the context would
            // load it again).
            Authentication authentication = context.getAuthentication();
            String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request, authentication);

            ZeroTrustAction action;
            double threatScore;

            // docs/agent A5-1: an agent acting for the user reads its own decision. On a token chain the bridge has
            // stamped the request by now; a session's context loads before the bridge runs, so it reads the user's.
            ZeroTrustSubject subject = ZeroTrustSubject.of(userId, delegationStamp(request));
            String decisionKey = ZeroTrustUserKey.of(subject != null ? subject.storageKey() : userId);
            CachedZeroTrustDecision cached = decisionCache.getIfPresent(decisionKey);
            if (cached != null && Objects.equals(cached.contextBindingHash, contextBindingHash)) {
                action = cached.action;
                threatScore = cached.threatScore;
            } else {
                action = subject != null ? subject.currentAction(actionRepository, contextBindingHash)
                        : actionRepository.getCurrentAction(userId, contextBindingHash);
                threatScore = threatScoreUtil.getThreatScore(userId);
                decisionCache.put(decisionKey, new CachedZeroTrustDecision(action, threatScore, contextBindingHash));
            }

            double trustScore = 1.0 - threatScore;
            // docs/agent A5-2: an agent's request the accountable person confirms runs with its own authorities
            // again; keep them before the CHALLENGE narrows them.
            if (action == ZeroTrustAction.CHALLENGE && subject != null && subject.agentId() != null) {
                ConfirmedAgentAuthentication.keep(request, context.getAuthentication());
            }
            adjustAuthoritiesByAction(context, action, userId, trustScore, threatScore);

            if (sessionId != null) {
                // QF-57: the authentication the request came with, not the one the action may have replaced it with
                // (a Zero Trust token no longer carries the access token, so its expiry would be lost).
                trackSession(userId, sessionId, authentication, request);
            }

            if (request != null) {
                request.setAttribute(ZERO_TRUST_ACTION_ATTR, action);
            }

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to apply Zero Trust to context for user: {}", userId, e);
            throw e;
        }
    }

    /** The delegation the bridge stamped on the request, or null (none yet, or no request). */
    private static DelegationStamp delegationStamp(HttpServletRequest request) {
        return request != null && request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP)
                instanceof DelegationStamp stamp ? stamp : null;
    }

    /**
     * QF-57: keeps the identifier among the user's tracked sessions, which a forced logout invalidates, until it is
     * certainly dead. A request writes only when the identifier is new since the last sweep or the deadline recorded
     * for it no longer covers what the request shows.
     */
    private void trackSession(String userId, String sessionId, Authentication authentication,
                              HttpServletRequest request) {
        TrackingDeadline wanted = trackingDeadline(sessionId, authentication, request, now());
        Instant recorded = registeredSessions.get(sessionId);
        if (recorded != null && wanted.coveredBy(recorded)) {
            return;
        }
        registeredSessions.put(sessionId, wanted.deadline() != null ? wanted.deadline() : UNTIMED);
        doRegisterSession(userId, sessionId, wanted.deadline());
    }

    /**
     * When the identifier is certainly dead, from what the request shows. The id of the request's HTTP session dies
     * once the container's idle limit has passed since its last request, this one; tracking runs half an idle limit
     * longer, so a request renews it at most once per half idle limit and it never ends before the container's own
     * deadline. A token's identifier dies with the token. An identifier nothing bounds (no HTTP session of that id or
     * one that never times out, and no token expiry) has no deadline.
     */
    private static TrackingDeadline trackingDeadline(String sessionId, Authentication authentication,
                                                     HttpServletRequest request, Instant now) {
        Integer idleSeconds = idleLimitSeconds(sessionId, request);
        if (idleSeconds != null) {
            if (idleSeconds <= 0) {
                return TrackingDeadline.NONE;
            }
            Instant containerDeadline = now.plusSeconds(idleSeconds).plus(CLOCK_SKEW);
            return new TrackingDeadline(containerDeadline.plusSeconds(idleSeconds / 2), containerDeadline);
        }
        Instant tokenExpiry = AISecurityContextSupport.accessTokenExpiry(authentication);
        if (tokenExpiry != null) {
            Instant deadline = (tokenExpiry.isAfter(now) ? tokenExpiry : now).plus(CLOCK_SKEW);
            return new TrackingDeadline(deadline, deadline);
        }
        return TrackingDeadline.NONE;
    }

    /** The idle limit of the request's HTTP session when the identifier is that session's id, or null. */
    private static Integer idleLimitSeconds(String sessionId, HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        try {
            HttpSession session = request.getSession(false);
            return session != null && sessionId.equals(session.getId()) ? session.getMaxInactiveInterval() : null;
        } catch (IllegalStateException invalidated) {
            return null;
        }
    }

    /** The time deadlines are measured against. */
    protected Instant now() {
        return Instant.now();
    }

    /**
     * QF-57: the most identifiers without a deadline tracked for one user; 0 or less tracks them all
     * ({@code contexa.security.zerotrust.session-tracking.max-untimed-sessions-per-user}).
     */
    protected int maxUntimedSessionsPerUser() {
        SecurityZeroTrustProperties.SessionTrackingSettings settings = securityZeroTrustProperties != null
                ? securityZeroTrustProperties.getSessionTracking() : null;
        return settings != null ? settings.getMaxUntimedSessionsPerUser()
                : SecurityZeroTrustProperties.SessionTrackingSettings.DEFAULT_MAX_UNTIMED_SESSIONS_PER_USER;
    }

    /** Lets an identifier the subclass stopped tracking register again on its next request. */
    protected final void releaseRegistration(String sessionId) {
        registeredSessions.remove(sessionId);
    }

    /**
     * Registers a session or token identifier for the user. {@code trackUntil} is when the identifier is certainly
     * dead (a token past its expiry, an HTTP session past its idle limit), after which it is no longer tracked; a
     * later registration with a later deadline extends it. Null means nothing bounds its life: such identifiers are
     * tracked until they are forgotten, up to {@link #maxUntimedSessionsPerUser()} per user, the least recently
     * registered released first.
     */
    protected abstract void doRegisterSession(String userId, String sessionId, Instant trackUntil);

    /** Registers an identifier nothing bounds the life of. */
    protected void doRegisterSession(String userId, String sessionId) {
        doRegisterSession(userId, sessionId, null);
    }

    /** Forgets a session the servlet container destroyed or replaced; it can no longer authenticate a request. */
    public void forgetSession(String sessionId) {
        if (sessionId == null) {
            return;
        }
        registeredSessions.remove(sessionId);
        doForgetSession(sessionId);
    }

    protected void doForgetSession(String sessionId) {
    }

    /**
     * The registration record only saves writes; clearing it makes live identifiers register once more with the
     * deadline their next request shows. Subclasses release their own entries past their deadlines.
     */
    @Override
    public void removeExpiredEntries() {
        registeredSessions.clear();
        doRemoveExpiredSessionData();
    }

    protected void doRemoveExpiredSessionData() {
    }

    @Override
    public void cleanupOnLogout(String userId, String sessionId) {
        if (userId == null) {
            return;
        }

        try {
            actionRepository.removeLogoutData(userId);
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to cleanup logout action data: userId={}", userId, e);
        }

        try {
            decisionCache.invalidate(ZeroTrustUserKey.of(userId));
            if (sessionId != null) {
                registeredSessions.remove(sessionId);
            }
            doCleanupSessionData(userId, sessionId);
        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to cleanup on logout: userId={}", userId, e);
        }
    }

    @Override
    public void invalidateDecisionCache(String userId) {
        if (userId != null) {
            decisionCache.invalidate(ZeroTrustUserKey.of(userId));
        }
    }

    protected abstract void doCleanupSessionData(String userId, String sessionId);

    protected void adjustAuthoritiesByAction(SecurityContext context, ZeroTrustAction action,
                                              String userId, double trustScore, double threatScore) {
        Authentication auth = context.getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return;
        }

        if (auth instanceof ZeroTrustAuthenticationToken ztToken && ztToken.getAction() == action) {
            return;
        }

        Collection<? extends GrantedAuthority> currentAuthorities = auth.getAuthorities();
        Set<GrantedAuthority> adjustedAuthorities = new HashSet<>();

        switch (action) {
            case ALLOW -> {
                addOriginalOrCurrentAuthorities(auth, adjustedAuthorities, currentAuthorities);
            }
            case BLOCK -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority(action.getGrantedAuthority()));
                log.warn("[ZeroTrust][AI Native] User BLOCKED (CRITICAL RISK): {}", userId);
            }
            case CHALLENGE -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority(action.getGrantedAuthority()));
            }
            case ESCALATE -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority(action.getGrantedAuthority()));
                // O-2: a decision outcome, not a failure.
                log.warn("[ZeroTrust][AI Native] Security REVIEW required (ESCALATE): {}", userId);
            }
            case PENDING_ANALYSIS -> {
                addOriginalOrCurrentAuthorities(auth, adjustedAuthorities, currentAuthorities);
                adjustedAuthorities.add(new SimpleGrantedAuthority(action.getGrantedAuthority()));
            }
        }

        if (!adjustedAuthorities.equals(new HashSet<>(currentAuthorities))) {
            ZeroTrustAuthenticationToken adjustedAuth = new ZeroTrustAuthenticationToken(
                    auth.getPrincipal(),
                    auth.getCredentials(),
                    adjustedAuthorities,
                    trustScore,
                    threatScore,
                    action
            );
            // The details hold the login facts recorded at sign-in; without them every later request of the
            // session would lose its login method, MFA state and authentication time.
            adjustedAuth.setDetails(auth.getDetails());
            context.setAuthentication(adjustedAuth);
        }
    }

    private void addOriginalOrCurrentAuthorities(Authentication auth,
                                                  Set<GrantedAuthority> target,
                                                  Collection<? extends GrantedAuthority> current) {
        Object principal = auth.getPrincipal();
        if (principal instanceof UnifiedCustomUserDetails userDetails) {
            target.addAll(userDetails.getOriginalAuthorities());
        } else {
            target.addAll(current);
        }
    }

    private record CachedZeroTrustDecision(ZeroTrustAction action, double threatScore, String contextBindingHash) {}

    /**
     * The deadline to register ({@code null}: none) and the time a recorded deadline must reach to still hold for
     * this request.
     */
    private record TrackingDeadline(Instant deadline, Instant mustReach) {

        static final TrackingDeadline NONE = new TrackingDeadline(null, null);

        boolean coveredBy(Instant recorded) {
            if (deadline == null) {
                return UNTIMED.equals(recorded);
            }
            return !UNTIMED.equals(recorded) && !recorded.isBefore(mustReach);
        }
    }
}
