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
import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.security.RequestPaths;
import io.contexa.contexacommon.security.ZeroTrustScreens;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockableResponseWrapper;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.blocking.ResponseBlockedException;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.service.UnanalysedRequestRecorder;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.WebUtil;
import io.contexa.contexacore.autonomous.agent.AgentContainmentService;
import io.contexa.contexacommon.security.bridge.OAuth2AuthenticationSupport;
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
import java.util.Objects;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.BooleanSupplier;

@Slf4j
public class ZeroTrustAccessControlFilter extends OncePerRequestFilter {

    public static final String BLOCK_MFA_FLOW_ATTRIBUTE = "BLOCK_MFA_FLOW";
    /** docs/agent A5-1: the error of an agent request its own block stops. */
    public static final String AGENT_BLOCKED = "AGENT_BLOCKED";

    private AgentContainmentService agentContainment;

    private static final Duration ESCALATE_RETRY_TTL = Duration.ofMinutes(5);
    private static final Duration BLOCK_MFA_VERIFIED_TTL = Duration.ofHours(1);
    private static final int RETRY_AFTER_SECONDS = 30;
    private static final String LOGOUT_PATH = "/logout";
    private static final String ADMIN_MFA_API = "/contexa/admin/api/mfa";

    /** The folders of Contexa's own decision screens and of the release of a decision. */
    private static final List<String> DECISION_FOLDERS = List.of(
            "/contexa/zero-trust",
            HostOwnedStepUp.STEP_UP_PATH,
            "/contexa/api/aiam/sse/zero-trust",
            "/contexa/api/aiam/zero-trust",
            "/contexa/admin/api/aiam/sse/zero-trust",
            "/contexa/admin/api/aiam/zero-trust");

    private final ZeroTrustActionRepository actionRedisRepository;
    private final AuthResponseWriter responseWriter;
    private final IBlockedUserRecorder blockedUserRecorder;
    private final ChallengeMfaInitializer challengeMfaInitializer;
    private final AuthUrlProvider authUrlProvider;
    private final BlockingSignalBroadcaster blockingDecisionRegistry;
    private final int maxBlockMfaAttempts;
    private final MfaFlowUrlRegistry mfaFlowUrlRegistry;
    private UnanalysedRequestRecorder unanalysedRequestRecorder;
    private BooleanSupplier enforcing = () -> true;
    private HostOwnedStepUp hostOwnedStepUp;
    private boolean monitoringHeaders = true;
    private ZeroTrustAction escalateTerminalAction;

    public ZeroTrustAccessControlFilter(
            ZeroTrustActionRepository actionRedisRepository,
            AuthResponseWriter responseWriter,
            IBlockedUserRecorder blockedUserRecorder,
            ChallengeMfaInitializer challengeMfaInitializer,
            AuthUrlProvider authUrlProvider,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            int maxBlockMfaAttempts) {
        this(actionRedisRepository, responseWriter, blockedUserRecorder, challengeMfaInitializer,
                authUrlProvider, blockingDecisionRegistry, maxBlockMfaAttempts, null);
    }

    public ZeroTrustAccessControlFilter(
            ZeroTrustActionRepository actionRedisRepository,
            AuthResponseWriter responseWriter,
            IBlockedUserRecorder blockedUserRecorder,
            ChallengeMfaInitializer challengeMfaInitializer,
            AuthUrlProvider authUrlProvider,
            BlockingSignalBroadcaster blockingDecisionRegistry,
            int maxBlockMfaAttempts,
            MfaFlowUrlRegistry mfaFlowUrlRegistry) {
        this.actionRedisRepository = actionRedisRepository;
        this.responseWriter = responseWriter;
        this.blockedUserRecorder = blockedUserRecorder;
        this.challengeMfaInitializer = challengeMfaInitializer;
        this.authUrlProvider = authUrlProvider;
        this.blockingDecisionRegistry = blockingDecisionRegistry;
        this.maxBlockMfaAttempts = maxBlockMfaAttempts;
        this.mfaFlowUrlRegistry = mfaFlowUrlRegistry;
    }

    /** Keeps a request this filter stops under the decision in force in its session (N-SES-1). */
    public void setUnanalysedRequestRecorder(UnanalysedRequestRecorder unanalysedRequestRecorder) {
        this.unanalysedRequestRecorder = unanalysedRequestRecorder;
    }

    /**
     * Whether decisions are enforced (the zero-trust mode is ENFORCE). Under SHADOW, OBSERVE or DISABLED nothing is
     * stopped: a restriction stored earlier stays stored and applies again under ENFORCE (ownership design Q-5).
     */
    public void setEnforcing(BooleanSupplier enforcing) {
        this.enforcing = enforcing != null ? enforcing : () -> true;
    }

    /**
     * Ownership HOST_OWNED: a BLOCK an administrator lets the user release by MFA goes to Contexa's verification-only
     * step-up instead of a Contexa MFA flow. Null under CONTEXA_OWNED.
     */
    public void setMonitoringHeaders(boolean monitoringHeaders) {
        this.monitoringHeaders = monitoringHeaders;
    }

    public void setHostOwnedStepUp(HostOwnedStepUp hostOwnedStepUp) {
        this.hostOwnedStepUp = hostOwnedStepUp;
    }

    /**
     * What an ESCALATE ends as, null while allow-escalate-final-action keeps it. A built-in repository ends a stored
     * ESCALATE when it is read; this filter ends one a repository of the application's own still answers with.
     */
    public void setEscalateTerminalAction(ZeroTrustAction escalateTerminalAction) {
        this.escalateTerminalAction = escalateTerminalAction;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = RequestPaths.of(request);
        return RequestPaths.isExactly(path, LOGOUT_PATH)
                || ZeroTrustScreens.isScreenResource(path)
                || ZeroTrustScreens.isDiscoveryDocument(path)
                || DECISION_FOLDERS.stream().anyMatch(folder -> RequestPaths.isWithin(path, folder));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // An anonymous visitor is nobody's user: all of them would share one decision, and one BLOCK would shut them all out.
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken || !enforcing.getAsBoolean()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Read before the decision in force: a BLOCK the response did not pass is one received after it.
        long responseStartNanos = System.nanoTime();
        // docs/agent A5-1: an agent acting for the user reads and keeps its own decisions under its own key; the
        // user's own requests keep the user ID.
        String principal = extractUserId(auth);
        ZeroTrustSubject subject = ZeroTrustSubject.of(principal, delegationStamp(request));
        boolean delegatedAgent = subject != null && subject.delegatedAgent();
        String userId = subject != null ? subject.storageKey() : principal;
        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
        ZeroTrustAction currentAction = subject != null
                ? subject.currentAction(actionRedisRepository, contextBindingHash)
                : actionRedisRepository.getCurrentAction(principal, contextBindingHash);

        if (currentAction != ZeroTrustAction.BLOCK
                && currentAction != ZeroTrustAction.ESCALATE
                && currentAction != ZeroTrustAction.PENDING_ANALYSIS) {
            passUntilBlocked(request, response, filterChain, userId, responseStartNanos);
            return;
        }

        String requestUri = RequestPaths.of(request);

        switch (currentAction) {
            case BLOCK -> {
                if (delegatedAgent) {
                    // An agent answers no factor made for people, so its block is not released by MFA (A5-3).
                    recordStopped(auth, ZeroTrustAction.BLOCK);
                    writeAgentBlocked(request, response);
                } else {
                    handleBlockWithMfa(request, response, filterChain, auth, userId, requestUri);
                }
            }
            case ESCALATE -> {
                recordStopped(auth, ZeroTrustAction.ESCALATE);
                handleEscalate(request, response, userId, subject);
            }
            case PENDING_ANALYSIS -> passUntilBlocked(request, response, filterChain, userId, responseStartNanos);
            default -> filterChain.doFilter(request, response);
        }
    }

    private void handleBlockWithMfa(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain,
                                    Authentication auth,
                                    String userId,
                                    String requestUri) throws IOException, ServletException {

        if (isBlockMfaPending(userId)) {
            long failCount = actionRedisRepository.getBlockMfaFailCount(userId);
            if (failCount >= maxBlockMfaAttempts) {
                log.warn("[ZeroTrustAccessControlFilter] BLOCK MFA attempts exhausted, denying MFA: userId={}", userId);
                recordStopped(auth, ZeroTrustAction.BLOCK);
                handleBlocked(request, response, userId);
                return;
            }

            if (isMfaRelatedPath(requestUri)) {
                filterChain.doFilter(request, response);
                return;
            }

            if (hostOwnedStepUp != null) {
                recordStopped(auth, ZeroTrustAction.BLOCK);
                sendToHostOwnedStepUp(request, response);
                return;
            }

            if (challengeMfaInitializer != null) {
                recordStopped(auth, ZeroTrustAction.BLOCK);
                initializeBlockMfa(request, response, auth, userId);
                return;
            }
        }

        recordStopped(auth, ZeroTrustAction.BLOCK);
        handleBlocked(request, response, userId);
    }

    /** A request stopped under the decision in force is kept in its session (N-SES-1). */
    private void recordStopped(Authentication auth, ZeroTrustAction action) {
        if (unanalysedRequestRecorder != null) {
            unanalysedRequestRecorder.recordRequest(auth, action);
        }
    }

    private boolean isBlockMfaPending(String userId) {
        return actionRedisRepository.isBlockMfaPending(userId);
    }

    /**
     * The sign-in a user under a BLOCK needs to release it, by the paths the running flows name: the folders those paths
     * usually sit in are shared with the application, and any path of the application stays stopped.
     */
    private boolean isMfaRelatedPath(String requestUri) {
        if (RequestPaths.isWithin(requestUri, ADMIN_MFA_API)) {
            return true;
        }
        // Under HOST_OWNED Contexa's sign-in does not run and the release goes through the step-up: the paths below are
        // the application's, and a user under a BLOCK does not reach them.
        if (hostOwnedStepUp != null) {
            return false;
        }
        if (mfaFlowUrlRegistry != null) {
            if (matchesAnyMfaUrl(requestUri, mfaFlowUrlRegistry.getAllMfaRelatedUrls())
                    || mfaFlowUrlRegistry.getAllMfaInProgressUrls().contains(requestUri)) {
                return true;
            }
        }
        if (authUrlProvider != null) {
            if (matchesAnyMfaUrl(requestUri, authUrlProvider.getAllMfaRelatedUrls())
                    || authUrlProvider.getMfaInProgressUrls().contains(requestUri)) {
                return true;
            }
        }
        return false;
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

    /** HOST_OWNED: the release of a BLOCK by MFA continues on Contexa's step-up, with its purpose. */
    private void sendToHostOwnedStepUp(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String stepUpUrl = hostOwnedStepUp.stepUpUrl(request) + "?purpose=block";
        if (WebUtil.isApiOrAjaxRequest(request)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", "BLOCK_MFA_REQUIRED");
            body.put("message", "MFA verification required for block resolution");
            body.put("mfaUrl", stepUpUrl);
            responseWriter.writeErrorResponse(
                    response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "BLOCK_MFA_REQUIRED",
                    "MFA verification required for block resolution",
                    request.getRequestURI(),
                    body);
        } else {
            response.sendRedirect(stepUpUrl);
        }
    }

    private void initializeBlockMfa(HttpServletRequest request,
                                    HttpServletResponse response,
                                    Authentication auth,
                                    String userId) throws IOException {
        try {
            request.setAttribute(BLOCK_MFA_FLOW_ATTRIBUTE, true);

            FactorContext context = challengeMfaInitializer.initializeChallengeFlow(
                    request, response, auth);

            String mfaPageUrl = buildMfaPageUrl(context, request);
            if (WebUtil.isApiOrAjaxRequest(request)) {
                Map<String, Object> body = new HashMap<>();
                body.put("error", "BLOCK_MFA_REQUIRED");
                body.put("message", "MFA verification required for block resolution");
                body.put("mfaUrl", mfaPageUrl);

                responseWriter.writeErrorResponse(
                        response,
                        HttpServletResponse.SC_UNAUTHORIZED,
                        "BLOCK_MFA_REQUIRED",
                        "MFA verification required for block resolution",
                        request.getRequestURI(),
                        body);
            } else {
                response.sendRedirect(mfaPageUrl);
            }
        } catch (Exception e) {
            log.error("[ZeroTrustAccessControlFilter] Failed to initialize block MFA: userId={}", userId, e);
            handleBlocked(request, response, userId);
        }
    }

    private AuthUrlProvider resolveProvider(FactorContext context) {
        if (context != null && context.getFlowTypeName() != null && mfaFlowUrlRegistry != null) {
            AuthUrlProvider flowProvider = mfaFlowUrlRegistry.getProvider(context.getFlowTypeName());
            if (flowProvider != null) {
                return flowProvider;
            }
        }
        return Objects.requireNonNull(authUrlProvider, "AuthUrlProvider must not be null in ZeroTrustAccessControlFilter");
    }

    private String buildMfaPageUrl(FactorContext context, HttpServletRequest request) {
        AuthUrlProvider provider = resolveProvider(context);
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

        return contextPath + provider.getMfaSelectFactor();
    }

    private void handleBlocked(HttpServletRequest request,
                               HttpServletResponse response,
                               String userId) throws IOException {

        String redirectUrl = request.getContextPath() + "/contexa/zero-trust/blocked";

        Map<String, Object> body = new HashMap<>();
        body.put("error", "ACCOUNT_BLOCKED");
        body.put("message", "Your account has been blocked due to security concerns");
        body.put("adminReviewRequired", true);
        body.put("redirectUrl", redirectUrl);

        if (WebUtil.isApiOrAjaxRequest(request)) {
            responseWriter.writeErrorResponse(
                    response,
                    HttpServletResponse.SC_FORBIDDEN,
                    "ACCOUNT_BLOCKED",
                    "Your account has been blocked due to security concerns",
                    request.getRequestURI(),
                    body);
        } else {
            response.sendRedirect(redirectUrl);
        }
    }

    private void handleEscalate(HttpServletRequest request,
                                HttpServletResponse response,
                                String userId,
                                ZeroTrustSubject subject) throws IOException {

        // A repository of the application's own may still answer ESCALATE. It ends here, never as a promotion; the
        // challenge filter has run by now, so this request is told to retry and the retry meets the action stored.
        // A terminal BLOCK goes on below: the promotion writes its flag and its record.
        if (escalateTerminalAction != null && escalateTerminalAction != ZeroTrustAction.BLOCK) {
            actionRedisRepository.saveAction(userId, escalateTerminalAction, Map.of());
            respondWithReviewInProgress(request, response);
            return;
        }

        ZeroTrustAction hashAction = actionRedisRepository.getActionFromHash(userId);

        if (hashAction != null) {
            actionRedisRepository.setEscalateRetry(userId, ESCALATE_RETRY_TTL);
            respondWithReviewInProgress(request, response);
            return;
        }

        if (actionRedisRepository.hasEscalateRetry(userId)) {
            respondWithReviewInProgress(request, response);
            return;
        }

        promoteEscalateToBlock(userId, request, response, subject);
    }

    private void respondWithReviewInProgress(HttpServletRequest request,
                                             HttpServletResponse response) throws IOException {

        String returnUrl = URLEncoder.encode(request.getRequestURI(), StandardCharsets.UTF_8);
        String redirectUrl = request.getContextPath()
                + "/contexa/zero-trust/analysis-pending?returnUrl=" + returnUrl;

        Map<String, Object> body = new HashMap<>();
        body.put("error", "SECURITY_REVIEW_IN_PROGRESS");
        body.put("message", "Security analysis in progress");
        body.put("retryAfterSeconds", RETRY_AFTER_SECONDS);
        body.put("redirectUrl", redirectUrl);

        response.setHeader("Retry-After", String.valueOf(RETRY_AFTER_SECONDS));

        if (WebUtil.isApiOrAjaxRequest(request)) {
            responseWriter.writeErrorResponse(
                    response,
                    423,
                    "SECURITY_REVIEW_IN_PROGRESS",
                    "Security analysis in progress",
                    request.getRequestURI(),
                    body);
        } else {
            response.sendRedirect(redirectUrl);
        }
    }

    private void promoteEscalateToBlock(String userId,
                                        HttpServletRequest request,
                                        HttpServletResponse response,
                                        ZeroTrustSubject subject) throws IOException {
        boolean delegatedAgent = subject != null && subject.delegatedAgent();
        boolean agent = subject != null && subject.agentId() != null;
        try {
            ZeroTrustAction currentAction = actionRedisRepository.getActionFromHash(userId);
            if (currentAction == ZeroTrustAction.BLOCK) {
                respondBlocked(request, response, userId, delegatedAgent);
                return;
            }

            String requestId = UUID.randomUUID().toString();
            String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);

            Map<String, Object> fields = new HashMap<>();
            fields.put("promotedFrom", "ESCALATE");
            fields.put("promotionReason", "ESCALATE TTL expired without resolution");
            if (contextBindingHash != null) {
                fields.put("contextBindingHash", contextBindingHash);
            }

            actionRedisRepository.saveAction(userId, ZeroTrustAction.BLOCK, fields);
            actionRedisRepository.setBlockedFlag(userId);

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String username = (auth != null) ? auth.getName() : null;

            // docs/agent A5-1, A5-3: an agent is no blocked person; the agent itself is stopped.
            if (agent && agentContainment != null) {
                agentContainment.onBlock(subject, clientIdOf(SecurityContextHolder.getContext().getAuthentication()),
                        null, "Auto-promoted from ESCALATE: TTL expired without resolution", requestId);
            }
            if (blockedUserRecorder != null && !agent) {
                // A3-3 (R-01): the block keeps the request's tenant for the release's learning.
                String tenantId = RequestInfoExtractor.extractTenantId(request);
                String reason = "Auto-promoted from ESCALATE: TTL expired without resolution";
                if (tenantId != null && !tenantId.isBlank()) {
                    blockedUserRecorder.recordBlock(requestId, userId, username, ZeroTrustAction.BLOCK.name(),
                            reason, request.getRemoteAddr(), request.getHeader("User-Agent"), tenantId);
                } else {
                    blockedUserRecorder.recordBlock(requestId, userId, username, ZeroTrustAction.BLOCK.name(),
                            reason, request.getRemoteAddr(), request.getHeader("User-Agent"));
                }
            }

            log.warn("[ZeroTrustAccessControlFilter] ESCALATE promoted to BLOCK: userId={}", userId);
        } catch (Exception e) {
            log.error("[ZeroTrustAccessControlFilter] Failed to promote ESCALATE to BLOCK: userId={}", userId, e);
        }

        respondBlocked(request, response, userId, delegatedAgent);
    }

    private void respondBlocked(HttpServletRequest request, HttpServletResponse response, String userId,
                                boolean delegatedAgent) throws IOException {
        if (delegatedAgent) {
            writeAgentBlocked(request, response);
        } else {
            handleBlocked(request, response, userId);
        }
    }

    /** docs/agent A5-1: an agent's request stopped by the agent's block; the person's account is not blocked. */
    private void writeAgentBlocked(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, Object> body = new HashMap<>();
        body.put("error", AGENT_BLOCKED);
        body.put("message", "This agent's requests for the user are stopped by a security decision");
        responseWriter.writeErrorResponse(
                response,
                HttpServletResponse.SC_FORBIDDEN,
                AGENT_BLOCKED,
                "This agent's requests for the user are stopped by a security decision",
                request.getRequestURI(),
                body);
    }

    /** docs/agent A5-3: what stops an agent whose escalation turned into a block. */
    public void setAgentContainment(AgentContainmentService agentContainment) {
        this.agentContainment = agentContainment;
    }

    /** The client the request's token was issued to, or null without a token. */
    private static String clientIdOf(Authentication authentication) {
        Map<String, Object> claims = OAuth2AuthenticationSupport.tokenClaims(authentication);
        Object clientId = claims != null ? claims.get("client_id") : null;
        if (clientId == null && claims != null) {
            clientId = claims.get("azp");
        }
        return clientId != null ? clientId.toString() : null;
    }

    /** The delegation the bridge stamped on the request, or null. */
    private static DelegationStamp delegationStamp(HttpServletRequest request) {
        return request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP) instanceof DelegationStamp stamp
                ? stamp : null;
    }

    /**
     * Lets the request go on with a response a BLOCK received after its start cuts. An ALLOW says nothing of what follows
     * it: a stream started in the seconds an ALLOW lasts runs far past it, and only a response that is wrapped can stop.
     */
    private void passUntilBlocked(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain,
                                  String userId,
                                  long responseStartNanos) throws ServletException, IOException {
        if (blockingDecisionRegistry == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String blockedRedirectUrl = resolveBlockedRedirectUrl();
        BlockableResponseWrapper wrapper = new BlockableResponseWrapper(
                response, blockingDecisionRegistry, userId, blockedRedirectUrl, responseStartNanos);
        if (!monitoringHeaders) {
            wrapper.omitMonitoringHeaders();
        }
        // The block signal stays after a cut, so the user's other responses in flight are cut too; the release
        // paths (MFA success, administrator, account purge) clear it.
        try {
            filterChain.doFilter(request, wrapper);
        } catch (IOException e) {
            if (wrapper.isCut()) {
                log.error("[ZeroTrustAccessControlFilter] Response aborted for blocked user (IOException): userId={}", userId);
                if (!response.isCommitted()) {
                    response.sendRedirect(request.getContextPath() + "/");
                    return;
                }
            }
            throw e;
        } catch (ResponseBlockedException e) {
            log.error("[ZeroTrustAccessControlFilter] Response aborted for blocked user (PrintWriter): userId={}", userId);
            if (!response.isCommitted()) {
                response.sendRedirect(request.getContextPath() + "/");
                return;
            }
            throw new IOException("Response blocked by security decision: userId=" + userId, e);
        }
    }

    private String resolveBlockedRedirectUrl() {
        if (authUrlProvider != null) {
            try {
                String urlPrefix = authUrlProvider.getUrlPrefix();
                return (urlPrefix != null ? urlPrefix : "") + "/contexa/zero-trust/blocked";
            } catch (Exception ignored) {
            }
        }
        return "/contexa/zero-trust/blocked";
    }

    private String extractUserId(Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return "unknown";
        }
        return auth.getName();
    }
}
