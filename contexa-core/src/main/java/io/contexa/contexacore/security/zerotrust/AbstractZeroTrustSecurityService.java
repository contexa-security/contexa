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
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.store.ExpiringStateStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.AISecurityContextSupport;
import io.contexa.contexacommon.security.UnifiedCustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
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
    private final Set<String> registeredSessions = ConcurrentHashMap.newKeySet();
    private static final Duration TOKEN_CLOCK_SKEW = Duration.ofSeconds(60);

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
            String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);

            ZeroTrustAction action;
            double threatScore;

            CachedZeroTrustDecision cached = decisionCache.getIfPresent(userId);
            if (cached != null && Objects.equals(cached.contextBindingHash, contextBindingHash)) {
                action = cached.action;
                threatScore = cached.threatScore;
            } else {
                action = actionRepository.getCurrentAction(userId, contextBindingHash);
                threatScore = threatScoreUtil.getThreatScore(userId);
                decisionCache.put(userId, new CachedZeroTrustDecision(action, threatScore, contextBindingHash));
            }

            double trustScore = 1.0 - threatScore;
            adjustAuthoritiesByAction(context, action, userId, trustScore, threatScore);

            if (sessionId != null && registeredSessions.add(sessionId)) {
                Instant tokenExpiry = AISecurityContextSupport.accessTokenExpiry(context.getAuthentication());
                doRegisterSession(userId, sessionId,
                        tokenExpiry != null ? tokenExpiry.plus(TOKEN_CLOCK_SKEW) : null);
            }

            if (request != null) {
                request.setAttribute(ZERO_TRUST_ACTION_ATTR, action);
            }

        } catch (Exception e) {
            log.error("[ZeroTrust] Failed to apply Zero Trust to context for user: {}", userId, e);
            throw e;
        }
    }

    /**
     * Registers a session or token identifier for the user. {@code trackUntil} is when the identifier is certainly
     * dead (a JWT past its expiry), or null for an HTTP session, which is forgotten when the container destroys it.
     */
    protected void doRegisterSession(String userId, String sessionId, Instant trackUntil) {
        doRegisterSession(userId, sessionId);
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
     * The registration set only prevents registering the same identifier twice; clearing it makes live identifiers
     * register once more with the same result. Subclasses release their own expired entries.
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
            decisionCache.invalidate(userId);
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
            decisionCache.invalidate(userId);
        }
    }

    protected abstract void doRegisterSession(String userId, String sessionId);

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
                log.error("[ZeroTrust][AI Native] User BLOCKED (CRITICAL RISK): {}", userId);
            }
            case CHALLENGE -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority(action.getGrantedAuthority()));
            }
            case ESCALATE -> {
                adjustedAuthorities.add(new SimpleGrantedAuthority(action.getGrantedAuthority()));
                log.error("[ZeroTrust][AI Native] Security REVIEW required (ESCALATE): {}", userId);
            }
            case PENDING_ANALYSIS -> {
                addOriginalOrCurrentAuthorities(auth, adjustedAuthorities, currentAuthorities);
                adjustedAuthorities.add(new SimpleGrantedAuthority(action.getGrantedAuthority()));
            }
        }

        if (!adjustedAuthorities.equals(new HashSet<>(currentAuthorities))) {
            Authentication adjustedAuth = new ZeroTrustAuthenticationToken(
                    auth.getPrincipal(),
                    auth.getCredentials(),
                    adjustedAuthorities,
                    trustScore,
                    threatScore,
                    action
            );
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
}
