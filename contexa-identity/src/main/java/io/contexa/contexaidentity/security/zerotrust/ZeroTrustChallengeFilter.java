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
package io.contexa.contexaidentity.security.zerotrust;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.HostOwnedIdentityNotice;
import io.contexa.contexacommon.security.RequestPaths;
import io.contexa.contexacommon.security.ZeroTrustScreens;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.execution.ZeroTrustChallengeFlowStarter;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.zerotrust.ZeroTrustAuthenticationToken;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.WebUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.BooleanSupplier;

@Slf4j
public class ZeroTrustChallengeFilter extends OncePerRequestFilter implements ZeroTrustChallengeFlowStarter {

    /** The answer to an agent under CHALLENGE: its accountable party confirms, it never steps up like a person (A1-13). */
    public static final String AGENT_CONFIRMATION_REQUIRED = "AGENT_CONFIRMATION_REQUIRED";

    private static final String LOCK_KEY_PREFIX = "mfa:challenge:init:";
    private static final Duration DEFAULT_LOCK_WAIT_TIME = Duration.ZERO;
    private static final Duration DEFAULT_LOCK_LEASE_TIME = Duration.ofSeconds(30);
    private static final int DEFAULT_BUSY_RETRY_AFTER_SECONDS = 3;
    private static final String LOGOUT_PATH = "/logout";
    private static final String ADMIN_MFA_API = "/contexa/admin/api/mfa";
    private static final String DECISION_SCREENS = "/contexa/zero-trust";
    private static final String AGENT_CONFIRMATION_API = "/contexa/api/agent-confirmations";
    /** The script Spring Security serves for the sign-in page of a passkey. */
    private static final String PASSKEY_SCRIPT = "/login/webauthn.js";

    private final ChallengeMfaInitializer challengeMfaInitializer;
    private final AuthResponseWriter responseWriter;
    private final AuthUrlProvider authUrlProvider;
    private final MfaSessionRepository sessionRepository;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final DistributedLockService lockService;
    private final MfaFlowUrlRegistry mfaFlowUrlRegistry;
    private final ZeroTrustActionRepository actionRepository;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;
    private UnanalysedRequestRecorder unanalysedRequestRecorder;
    private BooleanSupplier enforcing = () -> true;
    private HostOwnedStepUp hostOwnedStepUp;
    private AgentConfirmationGate agentConfirmationGate;
    private volatile boolean challengeProcedureAvailable = true;

    public ZeroTrustChallengeFilter(
            ChallengeMfaInitializer challengeMfaInitializer,
            AuthResponseWriter responseWriter,
            AuthUrlProvider authUrlProvider,
            MfaSessionRepository sessionRepository,
            MfaStateMachineIntegrator stateMachineIntegrator,
            DistributedLockService lockService,
            MfaFlowUrlRegistry mfaFlowUrlRegistry,
            ZeroTrustActionRepository actionRepository) {
        this(challengeMfaInitializer, responseWriter, authUrlProvider, sessionRepository,
                stateMachineIntegrator, lockService, mfaFlowUrlRegistry, actionRepository, null);
    }

    public ZeroTrustChallengeFilter(
            ChallengeMfaInitializer challengeMfaInitializer,
            AuthResponseWriter responseWriter,
            AuthUrlProvider authUrlProvider,
            MfaSessionRepository sessionRepository,
            MfaStateMachineIntegrator stateMachineIntegrator,
            DistributedLockService lockService,
            MfaFlowUrlRegistry mfaFlowUrlRegistry,
            ZeroTrustActionRepository actionRepository,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        this.challengeMfaInitializer = challengeMfaInitializer;
        this.responseWriter = responseWriter;
        this.authUrlProvider = authUrlProvider;
        this.sessionRepository = sessionRepository;
        this.stateMachineIntegrator = stateMachineIntegrator;
        this.lockService = lockService;
        this.mfaFlowUrlRegistry = mfaFlowUrlRegistry;
        this.actionRepository = actionRepository;
        this.securityZeroTrustProperties = securityZeroTrustProperties;
    }

    /** Whether the host has an MFA flow in which a challenged user can step up; set when the chains are built. */
    /** Keeps a request this filter stops under the decision in force in its session (N-SES-1). */
    public void setUnanalysedRequestRecorder(UnanalysedRequestRecorder unanalysedRequestRecorder) {
        this.unanalysedRequestRecorder = unanalysedRequestRecorder;
    }

    /** docs/agent A5-2: where agents' requests meet the confirmation of the person accountable for them. */
    public void setAgentConfirmationGate(AgentConfirmationGate agentConfirmationGate) {
        this.agentConfirmationGate = agentConfirmationGate;
    }

    /**
     * Ownership HOST_OWNED: the application owns sign-in, so a CHALLENGE is answered by Contexa's verification-only
     * step-up and no Contexa MFA flow (flow state, session) is started. Null under CONTEXA_OWNED.
     */
    public void setHostOwnedStepUp(HostOwnedStepUp hostOwnedStepUp) {
        this.hostOwnedStepUp = hostOwnedStepUp;
    }

    /** Whether decisions are enforced (the zero-trust mode is ENFORCE); see {@link #doFilterInternal}. */
    public void setEnforcing(BooleanSupplier enforcing) {
        this.enforcing = enforcing != null ? enforcing : () -> true;
    }

    public void setChallengeProcedureAvailable(boolean challengeProcedureAvailable) {
        this.challengeProcedureAvailable = challengeProcedureAvailable;
    }

    /** Whether the host has an MFA flow in which a user can step up. */
    public boolean challengeProcedureAvailable() {
        return challengeProcedureAvailable;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = RequestPaths.of(request);

        if (RequestPaths.isExactly(path, LOGOUT_PATH) || ConsoleSession.onReleasePath(request)) {
            return true;
        }

        if (hostOwnedStepUp == null && isContexaSignInPath(path)) {
            return true;
        }

        if (RequestPaths.isWithin(path, ADMIN_MFA_API)) {
            return true;
        }

        if (RequestPaths.isWithin(path, DECISION_SCREENS) || RequestPaths.isWithin(path, HostOwnedStepUp.STEP_UP_PATH)) {
            return true;
        }

        // The scripts and styles of the screens of a decision (a request for them would be answered with the screen).
        if (ZeroTrustScreens.isScreenResource(path)) {
            return true;
        }

        // docs/agent A5-2: the agent polls its confirmation while its request waits for it.
        if (RequestPaths.isWithin(path, AGENT_CONFIRMATION_API)) {
            return true;
        }

        return ZeroTrustScreens.isDiscoveryDocument(path);
    }

    /**
     * The paths of Contexa's own sign-in, which runs only where Contexa owns it. Under HOST_OWNED nothing of Contexa
     * answers there (its step-up lives under {@link HostOwnedStepUp#STEP_UP_PATH}): they are the application's paths, and
     * a stored decision applies to them as to any other. They are the paths the running flows name: the folders those
     * paths usually sit in are shared with the application.
     */
    private boolean isContexaSignInPath(String path) {
        return (authUrlProvider != null && (matchesAnyMfaUrl(path, authUrlProvider.getAllMfaRelatedUrls())
                        || RequestPaths.isExactly(path, authUrlProvider.getPrimaryRestLoginProcessing())
                        || RequestPaths.isExactly(path, authUrlProvider.getSinglePasskeyLoginPage())
                        || RequestPaths.isExactly(path, authUrlProvider.getSinglePasskeyLoginProcessing())))
                || (mfaFlowUrlRegistry != null && matchesAnyMfaUrl(path, mfaFlowUrlRegistry.getAllMfaRelatedUrls()))
                || RequestPaths.isExactly(path, PASSKEY_SCRIPT);
    }

    private boolean matchesAnyMfaUrl(String requestUri, Set<String> mfaUrls) {
        for (String mfaUrl : mfaUrls) {
            if (!StringUtils.hasText(mfaUrl) || "/".equals(mfaUrl)) {
                continue;
            }
            if (RequestPaths.isWithin(requestUri, mfaUrl)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (hostOwnedStepUp != null) {
            // Ownership design S-7: an application that signs the user in after these filters is reported once.
            HostOwnedIdentityNotice.markWhenNoUser(request, auth);
        }

        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }

        String userId = extractUserId(auth);
        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
        // docs/agent A5-1: an agent acting for the user reads its own decision, not the user's.
        ZeroTrustSubject subject = ZeroTrustSubject.of(userId, delegationStamp(request),
                RequestInfoExtractor.extractTenantId(request));
        ZeroTrustAction currentAction = subject != null
                ? subject.currentAction(actionRepository, contextBindingHash)
                : actionRepository.getCurrentAction(userId, contextBindingHash);

        // docs/agent A5-2, F-2: an agent's request meets its accountable person's confirmation, not a person's MFA.
        if (agentConfirmationGate != null && subject != null && isAgentRequest(request)) {
            boolean went = agentConfirmationGate.filter(request, response, filterChain, subject, currentAction);
            if (!went && currentAction == ZeroTrustAction.CHALLENGE && unanalysedRequestRecorder != null) {
                unanalysedRequestRecorder.recordRequest(auth, ZeroTrustAction.CHALLENGE);
            }
            return;
        }

        // Ownership design Q-5: under SHADOW, OBSERVE or DISABLED a stored CHALLENGE stops nothing (the agent gate above
        // records and lets agents on by itself).
        if (currentAction != ZeroTrustAction.CHALLENGE || !enforcing.getAsBoolean()) {
            filterChain.doFilter(request, response);
            return;
        }

        // HOST_OWNED: a re-authentication the application made after the CHALLENGE answers it; the request goes on.
        String decisionKey = subject != null ? subject.storageKey() : userId;
        if (hostOwnedStepUp != null && !isAgentRequest(request)
                && hostOwnedStepUp.resolvedByHostReauthentication(request, auth, decisionKey)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Every way on from here stops the request; the session keeps it under the CHALLENGE (N-SES-1).
        if (unanalysedRequestRecorder != null) {
            unanalysedRequestRecorder.recordRequest(auth, ZeroTrustAction.CHALLENGE);
        }

        if (isAgentRequest(request)) {
            writeAgentConfirmationRequired(response, request);
            return;
        }

        if (hostOwnedStepUp != null) {
            writeHostOwnedStepUp(request, response);
            return;
        }

        if (!challengeProcedureAvailable) {
            writeChallengeWithoutProcedure(response, request);
            return;
        }

        if (handleExistingSession(request, response, filterChain)) {
            return;
        }

        String lockKey = LOCK_KEY_PREFIX + userId;
        String lockOwner = Thread.currentThread().getName() + ":" + UUID.randomUUID();

        Duration lockWaitTime = resolveLockWaitTime();
        Duration lockLeaseTime = resolveLockLeaseTime();
        if (!tryAcquireChallengeLock(lockKey, lockOwner, lockLeaseTime, lockWaitTime)) {
            log.warn("MFA challenge initialization is already in progress: lockKey={}, lockWaitTime={}, lockLeaseTime={}, retryAfterSeconds={}",
                    lockKey, lockWaitTime, lockLeaseTime, resolveBusyRetryAfterSeconds());
            writeBusyRetryResponse(response, request);
            return;
        }

        try {
            if (handleExistingChallengeSession(request, response, filterChain)) {
                return;
            }
            FactorContext context = challengeMfaInitializer.initializeChallengeFlow(request, response, auth);
            redirectToMfaPage(context, request, response);

        } catch (ChallengeMfaInitializer.ChallengeMfaInitializationException e) {
            log.error("Failed to initialize challenge MFA flow: {}", e.getMessage());
            handleInitializationError(response, request, e);
        } catch (Exception e) {
            log.error("Unexpected error in ZeroTrustChallengeFilter", e);
            handleInitializationError(response, request, e);
        } finally {
            lockService.unlock(lockKey, lockOwner);
        }
    }

    /**
     * docs/agent A5-2: an agent's request a CHALLENGE decided in the request stopped meets the confirmation gate, as
     * a request under a CHALLENGE in force does: the gate asks the accountable person and writes the answer.
     */
    @Override
    public boolean answerAgentChallenge(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (agentConfirmationGate == null || auth == null || !auth.isAuthenticated() || !isAgentRequest(request)) {
            return false;
        }
        ZeroTrustSubject subject = ZeroTrustSubject.of(extractUserId(auth), delegationStamp(request),
                RequestInfoExtractor.extractTenantId(request));
        try {
            return agentConfirmationGate.answerDecidedChallenge(request, response, subject);
        } catch (IOException | RuntimeException e) {
            log.error("Could not ask for the confirmation of an agent's request: agentId={}",
                    subject != null ? subject.agentId() : null, e);
            return false;
        }
    }

    /**
     * Starts the step-up flow for a CHALLENGE decided inside the request (a synchronous {@code @Protectable}), with
     * the same lock and the same reuse of an already started flow as a request this filter challenges, and returns the
     * MFA page the user continues on. The caller writes its own answer, so nothing is written here.
     */
    @Override
    public Optional<String> start(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || isAgentRequest(request)) {
            return Optional.empty();
        }
        if (hostOwnedStepUp != null) {
            // HOST_OWNED: no flow is started (no flow state, no session); the answer names the step-up.
            return Optional.of(hostOwnedStepUp.stepUpUrl(request));
        }
        if (!challengeProcedureAvailable) {
            return Optional.empty();
        }
        FactorContext started = startedChallengeContext(request);
        if (started != null) {
            return Optional.of(buildMfaPageUrl(started, request));
        }
        String lockKey = LOCK_KEY_PREFIX + extractUserId(auth);
        String lockOwner = Thread.currentThread().getName() + ":" + UUID.randomUUID();
        if (!tryAcquireChallengeLock(lockKey, lockOwner, resolveLockLeaseTime(), resolveLockWaitTime())) {
            return Optional.empty();
        }
        try {
            started = startedChallengeContext(request);
            FactorContext context = started != null
                    ? started
                    : challengeMfaInitializer.initializeChallengeFlow(request, response, auth);
            return Optional.of(buildMfaPageUrl(context, request));
        } catch (ChallengeMfaInitializer.ChallengeMfaInitializationException e) {
            log.error("Failed to initialize challenge MFA flow for a decision made in the request: {}", e.getMessage());
            return Optional.empty();
        } finally {
            lockService.unlock(lockKey, lockOwner);
        }
    }

    /** The challenge flow already started for this session and not finished yet, or null. */
    private FactorContext startedChallengeContext(HttpServletRequest request) {
        String sessionId = sessionRepository.getSessionId(request);
        if (sessionId == null || !sessionRepository.existsSession(sessionId)) {
            return null;
        }
        FactorContext context = stateMachineIntegrator.loadFactorContext(sessionId);
        if (context == null || !Boolean.TRUE.equals(context.getBooleanAttribute("challengeInitiated"))
                || context.getCurrentState().isTerminal()) {
            return null;
        }
        return context;
    }

    private boolean tryAcquireChallengeLock(
            String lockKey,
            String lockOwner,
            Duration lockLeaseTime,
            Duration lockWaitTime) {
        if (lockWaitTime == null || lockWaitTime.isZero() || lockWaitTime.isNegative()) {
            return lockService.tryLock(lockKey, lockOwner, lockLeaseTime);
        }
        return lockService.tryLockWithWait(lockKey, lockOwner, lockLeaseTime, lockWaitTime);
    }

    private Duration resolveLockWaitTime() {
        if (securityZeroTrustProperties == null || securityZeroTrustProperties.getChallenge() == null) {
            return DEFAULT_LOCK_WAIT_TIME;
        }
        Duration configured = securityZeroTrustProperties.getChallenge().getLockWaitTime();
        return configured != null && !configured.isNegative()
                ? configured
                : DEFAULT_LOCK_WAIT_TIME;
    }

    private Duration resolveLockLeaseTime() {
        if (securityZeroTrustProperties == null || securityZeroTrustProperties.getChallenge() == null) {
            return DEFAULT_LOCK_LEASE_TIME;
        }
        Duration configured = securityZeroTrustProperties.getChallenge().getLockLeaseTime();
        return configured != null && !configured.isZero() && !configured.isNegative()
                ? configured
                : DEFAULT_LOCK_LEASE_TIME;
    }

    private int resolveBusyRetryAfterSeconds() {
        if (securityZeroTrustProperties == null || securityZeroTrustProperties.getChallenge() == null) {
            return DEFAULT_BUSY_RETRY_AFTER_SECONDS;
        }
        int configured = securityZeroTrustProperties.getChallenge().getBusyRetryAfterSeconds();
        return configured > 0 ? configured : DEFAULT_BUSY_RETRY_AFTER_SECONDS;
    }

    private void writeBusyRetryResponse(HttpServletResponse response, HttpServletRequest request) throws IOException {
        int retryAfterSeconds = resolveBusyRetryAfterSeconds();
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("retryAfterSeconds", retryAfterSeconds);

        responseWriter.writeErrorResponse(
                response,
                HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                "MFA_BUSY_RETRY",
                "MFA challenge is already being initialized. Retry shortly.",
                request.getRequestURI(),
                errorDetails
        );
    }

    private boolean handleExistingSession(HttpServletRequest request,
                                          HttpServletResponse response,
                                          FilterChain filterChain) throws ServletException, IOException {
        String sessionId = sessionRepository.getSessionId(request);
        if (sessionId == null || !sessionRepository.existsSession(sessionId)) {
            return false;
        }

        FactorContext context = stateMachineIntegrator.loadFactorContext(sessionId);
        if (context == null) {
            sessionRepository.removeSession(sessionId, request, response);
            return false;
        }

        if (!Boolean.TRUE.equals(context.getBooleanAttribute("challengeInitiated"))) {
            stateMachineIntegrator.cleanupSession(request, response);
            return false;
        }

        if (context.getCurrentState().isTerminal()) {
            stateMachineIntegrator.cleanupSession(request, response);
            return false;
        }

        redirectToMfaPage(context, request, response);
        return true;
    }

    private boolean handleExistingChallengeSession(HttpServletRequest request,
                                                   HttpServletResponse response,
                                                   FilterChain filterChain) throws ServletException, IOException {
        String sessionId = sessionRepository.getSessionId(request);
        if (sessionId == null || !sessionRepository.existsSession(sessionId)) {
            return false;
        }

        FactorContext context = stateMachineIntegrator.loadFactorContext(sessionId);
        if (context == null || !Boolean.TRUE.equals(context.getBooleanAttribute("challengeInitiated"))) {
            return false;
        }

        redirectToMfaPage(context, request, response);
        return true;
    }

    private void redirectToMfaPage(FactorContext context,
                                   HttpServletRequest request,
                                   HttpServletResponse response) throws IOException {

        String mfaPageUrl = buildMfaPageUrl(context, request);
        String challengeNoticeUrl = buildChallengeNoticeUrl(mfaPageUrl, request);

        if (WebUtil.isApiOrAjaxRequest(request)) {
            writeMfaChallengeResponse(response, request, context, mfaPageUrl, challengeNoticeUrl);
        } else {
            response.sendRedirect(challengeNoticeUrl);
        }
    }

    /** The delegation the bridge stamped on the request, or null. */
    private static DelegationStamp delegationStamp(HttpServletRequest request) {
        return request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP) instanceof DelegationStamp stamp
                ? stamp : null;
    }

    /** Whether the bridge named an agent for the request; the bridge filter runs before this one in every chain. */
    private static boolean isAgentRequest(HttpServletRequest request) {
        return request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP) instanceof DelegationStamp stamp
                && stamp.agentId() != null && !stamp.agentId().isBlank();
    }

    /**
     * An agent cannot answer the factors made for people, so a CHALLENGE stops its request until the agent's
     * accountable party (its delegator, or its sponsor when it acts on its own) confirms it (A5-2).
     */
    private void writeAgentConfirmationRequired(HttpServletResponse response, HttpServletRequest request)
            throws IOException {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("error", AGENT_CONFIRMATION_REQUIRED);
        responseBody.put("message", "The agent's accountable party must confirm this request");
        responseWriter.writeErrorResponse(
                response,
                HttpServletResponse.SC_FORBIDDEN,
                AGENT_CONFIRMATION_REQUIRED,
                "The agent's accountable party must confirm this request",
                request.getRequestURI(),
                responseBody
        );
    }

    /**
     * HOST_OWNED: a browser goes to the notice that leads to Contexa's step-up; an API client gets 401 with the same
     * code and links as under CONTEXA_OWNED, without the flow fields (no flow is started).
     */
    private void writeHostOwnedStepUp(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String stepUpUrl = hostOwnedStepUp.stepUpUrl(request);
        String challengeNoticeUrl = ZeroTrustScreens.challengeRequired(request, stepUpUrl);
        if (!WebUtil.isApiOrAjaxRequest(request)) {
            response.sendRedirect(challengeNoticeUrl);
            return;
        }
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("error", "MFA_CHALLENGE_REQUIRED");
        responseBody.put("message", "MFA verification required");
        responseBody.put("mfaUrl", stepUpUrl);
        responseBody.put("challengeNoticeUrl", challengeNoticeUrl);
        responseWriter.writeErrorResponse(
                response,
                HttpServletResponse.SC_UNAUTHORIZED,
                "MFA_CHALLENGE_REQUIRED",
                "MFA verification required",
                request.getRequestURI(),
                responseBody
        );
    }

    /** A host without an MFA flow cannot step the user up, so the request is refused without opening a procedure. */
    private void writeChallengeWithoutProcedure(HttpServletResponse response, HttpServletRequest request)
            throws IOException {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("error", "ZERO_TRUST_CHALLENGE");
        responseBody.put("message", "Additional verification is required and this application offers no MFA flow");
        responseWriter.writeErrorResponse(
                response,
                HttpServletResponse.SC_UNAUTHORIZED,
                "ZERO_TRUST_CHALLENGE",
                "Additional verification is required and this application offers no MFA flow",
                request.getRequestURI(),
                responseBody
        );
    }

    private String buildChallengeNoticeUrl(String mfaPageUrl, HttpServletRequest request) {
        String encodedMfaUrl = URLEncoder.encode(mfaPageUrl, StandardCharsets.UTF_8);
        return request.getContextPath() + "/contexa/zero-trust/challenge-required?mfaUrl=" + encodedMfaUrl;
    }

    private void writeMfaChallengeResponse(HttpServletResponse response,
                                           HttpServletRequest request,
                                           FactorContext context,
                                           String mfaPageUrl,
                                           String challengeNoticeUrl) throws IOException {
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("error", "MFA_CHALLENGE_REQUIRED");
        responseBody.put("message", "MFA verification required");
        responseBody.put("mfaUrl", mfaPageUrl);
        responseBody.put("challengeNoticeUrl", challengeNoticeUrl);
        responseBody.put("sessionId", context.getMfaSessionId());
        responseBody.put("currentState", context.getCurrentState().name());

        AuthType currentFactor = context.getCurrentProcessingFactor();
        if (currentFactor != null) {
            responseBody.put("currentFactor", currentFactor.name());
        }

        responseWriter.writeErrorResponse(
                response,
                HttpServletResponse.SC_UNAUTHORIZED,
                "MFA_CHALLENGE_REQUIRED",
                "MFA verification required",
                request.getRequestURI(),
                responseBody
        );
    }

    private AuthUrlProvider resolveProvider(HttpServletRequest request) {
        FactorContext ctx = stateMachineIntegrator.loadFactorContextFromRequest(request);
        if (ctx != null && ctx.getFlowTypeName() != null && mfaFlowUrlRegistry != null) {
            AuthUrlProvider flowProvider = mfaFlowUrlRegistry.getProvider(ctx.getFlowTypeName());
            if (flowProvider != null) {
                return flowProvider;
            }
        }
        return authUrlProvider;
    }

    private String buildMfaPageUrl(FactorContext context, HttpServletRequest request) {
        AuthUrlProvider provider = resolveProvider(request);
        MfaState currentState = context.getCurrentState();
        String contextPath = request.getContextPath();

        if (currentState == MfaState.FACTOR_CHALLENGE_PRESENTED_AWAITING_VERIFICATION) {
            AuthType currentFactor = context.getCurrentProcessingFactor();
            if (currentFactor != null) {
                return switch (currentFactor) {
                    case MFA_OTT -> contextPath + provider.getOttRequestCodeUi();
                    case MFA_PASSKEY -> contextPath + provider.getPasskeyChallengeUi();
                    default -> contextPath + provider.getMfaSelectFactor();
                };
            }
        }

        if (currentState == MfaState.AWAITING_FACTOR_SELECTION ||
                currentState == MfaState.PRIMARY_AUTHENTICATION_COMPLETED) {
            return contextPath + provider.getMfaSelectFactor();
        }

        return contextPath + provider.getMfaSelectFactor();
    }

    private void handleInitializationError(HttpServletResponse response, HttpServletRequest request,
                                           Exception e) throws IOException {
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("error", "MFA_INIT_FAILED");
        errorDetails.put("message", "Failed to initialize MFA challenge flow");

        responseWriter.writeErrorResponse(
                response,
                HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "MFA_INIT_FAILED",
                "Failed to initialize MFA challenge",
                request.getRequestURI(),
                errorDetails
        );
    }

    private boolean hasAuthority(Authentication auth) {
        if (auth.getAuthorities() == null) {
            return false;
        }
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(ZeroTrustAction.CHALLENGE.getGrantedAuthority()::equals);
    }

    private String extractUserId(Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return "unknown";
        }
        return auth.getName();
    }

}
