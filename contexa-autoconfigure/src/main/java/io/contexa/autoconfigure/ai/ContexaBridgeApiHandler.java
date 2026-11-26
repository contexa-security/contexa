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
package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.subject.ContexaBridge;
import io.contexa.contexacommon.security.bridge.subject.ContexaBridgeResult;
import io.contexa.contexacommon.security.bridge.subject.ContexaBridgeResult.Outcome;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.ContexaUsers;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.event.support.HostSignInEvents;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurgeResult;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurger;
import io.contexa.contexacore.autonomous.store.LoginFailureRecording;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * What Contexa does for the optional calls of a legacy application (docs/agent/bridge-v2-B5-2-B5-3-설계안.md 2): each
 * reuses what Contexa already does for a sign-in, a failed one, a sign-out and a deleted account, so a call ends in the
 * same state as Contexa's own events do. The parts come from the modules that own them, which only the auto-configuration
 * sees together. In mode FULL Contexa's main chain signs the application's users in and out itself, so the calls about a
 * sign-in have nothing to do there.
 */
@Slf4j
final class ContexaBridgeApiHandler implements ContexaBridge.Handler, ContexaUsers.Handler {

    static final String SIGNED_IN_BY = "ContexaBridge";

    private final BridgeProperties properties;
    private final ObjectProvider<BridgeResolutionFilter> bridge;
    private final ObjectProvider<ZeroTrustEventPublisher> publisher;
    private final ObjectProvider<SecurityContextDataStore> securityContext;
    private final ObjectProvider<HostSignInEvents> signInEvents;
    private final ObjectProvider<SessionManagementService> sessions;
    private final ObjectProvider<ZeroTrustSecurityService> zeroTrust;
    private final ObjectProvider<SessionIdResolver> sessionIds;
    private final ObjectProvider<UserEngineStatePurger> purger;
    private final ObjectProvider<BridgeRuntimeSupport> runtime;

    ContexaBridgeApiHandler(BridgeProperties properties,
                            ObjectProvider<BridgeResolutionFilter> bridge,
                            ObjectProvider<ZeroTrustEventPublisher> publisher,
                            ObjectProvider<SecurityContextDataStore> securityContext,
                            ObjectProvider<HostSignInEvents> signInEvents,
                            ObjectProvider<SessionManagementService> sessions,
                            ObjectProvider<ZeroTrustSecurityService> zeroTrust,
                            ObjectProvider<SessionIdResolver> sessionIds,
                            ObjectProvider<UserEngineStatePurger> purger,
                            ObjectProvider<BridgeRuntimeSupport> runtime) {
        this.properties = properties;
        this.bridge = bridge;
        this.publisher = publisher;
        this.securityContext = securityContext;
        this.signInEvents = signInEvents;
        this.sessions = sessions;
        this.zeroTrust = zeroTrust;
        this.sessionIds = sessionIds;
        this.purger = purger;
        this.runtime = runtime;
    }

    /**
     * The user becomes the identity of the request and its copy is waited for, as a user the application names on the
     * request is, and the sign-in goes to the decisions once, as the event of a Spring Security sign-in does.
     */
    @Override
    public ContexaBridgeResult signedIn(HttpServletRequest request, ContexaSubject subject) {
        if (contexaSignsTheUsersIn()) {
            return notApplicable();
        }
        BridgeResolutionFilter resolution = bridge.getIfAvailable();
        if (resolution == null) {
            return ContexaBridgeResult.of(Outcome.NOT_INITIALIZED, "the bridge is off");
        }
        ContexaIdentity identity = resolution.signedIn(request, subject);
        if (!identity.isResolved()) {
            return ContexaBridgeResult.of(Outcome.INVALID, "the user id breaks its rules");
        }
        ZeroTrustEventPublisher events = publisher.getIfAvailable();
        if (events != null) {
            events.publishNamedSignIn(request, Map.of(
                    "authenticationType", "HOST_SIGN_IN",
                    "signedInBy", SIGNED_IN_BY,
                    "action", ZeroTrustAction.ALLOW.name()));
        }
        return ContexaBridgeResult.done();
    }

    /** Counted as the failed sign-ins of the user, as a failure Spring Security reports is, and from then on known. */
    @Override
    public ContexaBridgeResult signInFailed(HttpServletRequest request, String userId) {
        if (contexaSignsTheUsersIn()) {
            return notApplicable();
        }
        SecurityContextDataStore store = securityContext.getIfAvailable();
        if (store == null) {
            return ContexaBridgeResult.of(Outcome.NOT_INITIALIZED, "the decisions are off");
        }
        HostSignInEvents events = signInEvents.getIfAvailable();
        if (events != null) {
            events.reached();
        }
        LoginFailureRecording.recordOnce(store, request, userId, null);
        return ContexaBridgeResult.done();
    }

    /**
     * The tracking of the request's session ends, and what Contexa keeps for the sign-in goes as at a logout of
     * Contexa's own chain; a block, a challenge or a review of the user stays. Each part is done though another failed.
     */
    @Override
    public ContexaBridgeResult signedOut(HttpServletRequest request, String userId) {
        if (contexaSignsTheUsersIn()) {
            return notApplicable();
        }
        List<String> failed = new ArrayList<>();
        HttpSession session = request.getSession(false);
        SessionManagementService tracked = sessions.getIfAvailable();
        if (session != null && tracked != null) {
            RequestPathScope.enter();
            try {
                tracked.endTracking(session.getId());
            } catch (RuntimeException e) {
                log.error("[Bridge] The tracking of a signed-out session could not end: {}", e.toString());
                failed.add("session tracking");
            } finally {
                RequestPathScope.leave();
            }
        }
        ZeroTrustSecurityService decisions = zeroTrust.getIfAvailable();
        if (decisions != null) {
            try {
                SessionIdResolver resolver = sessionIds.getIfAvailable();
                decisions.cleanupOnLogout(userId, resolver != null ? resolver.resolve(request) : null);
            } catch (RuntimeException e) {
                log.error("[Bridge] What Contexa kept for a signed-out user could not be let go of: {}", e.toString());
                failed.add("decision state");
            }
        }
        return failed.isEmpty()
                ? ContexaBridgeResult.done()
                : ContexaBridgeResult.of(Outcome.FAILED, "not ended: " + String.join(", ", failed));
    }

    /**
     * The user's copy and every state Contexa keeps for the user's decisions go ({@link UserEngineStatePurger}), and the
     * request path lets go of the copy it kept: the same user id coming again is a new user.
     */
    @Override
    public ContexaBridgeResult delete(String userId) {
        UserEngineStatePurger engine = purger.getIfAvailable();
        if (engine == null) {
            return ContexaBridgeResult.of(Outcome.NOT_INITIALIZED, "the decisions are off");
        }
        UserEngineStatePurgeResult purged = engine.purge(userId);
        BridgeRuntimeSupport kept = runtime.getIfAvailable();
        if (kept != null) {
            kept.forget(userId);
        }
        return purged.complete()
                ? ContexaBridgeResult.done()
                : ContexaBridgeResult.of(Outcome.FAILED, "not deleted: " + String.join(", ", purged.failedSteps().keySet()));
    }

    private boolean contexaSignsTheUsersIn() {
        return properties.operatingBehaviour().signsInTheApplicationsUsers();
    }

    private static ContexaBridgeResult notApplicable() {
        return ContexaBridgeResult.of(Outcome.NOT_APPLICABLE, "mode FULL signs the application's users in and out itself");
    }
}
