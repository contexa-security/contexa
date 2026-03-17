package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.blocking.BlockableResponseWrapper;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.blocking.ResponseBlockedException;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
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
import java.util.Set;
import java.util.UUID;

@Slf4j
public class ZeroTrustAccessControlFilter extends OncePerRequestFilter {

    public static final String BLOCK_MFA_FLOW_ATTRIBUTE = "BLOCK_MFA_FLOW";

    private static final Duration ESCALATE_RETRY_TTL = Duration.ofMinutes(5);
    private static final Duration BLOCK_MFA_VERIFIED_TTL = Duration.ofHours(1);
    private static final int RETRY_AFTER_SECONDS = 30;

    private final ZeroTrustActionRepository actionRedisRepository;
    private final AuthResponseWriter responseWriter;
    private final IBlockedUserRecorder blockedUserRecorder;
    private final ChallengeMfaInitializer challengeMfaInitializer;
    private final AuthUrlProvider authUrlProvider;
    private final BlockingSignalBroadcaster blockingDecisionRegistry;
    private final int maxBlockMfaAttempts;
    private final MfaFlowUrlRegistry mfaFlowUrlRegistry;

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

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (StringUtils.hasText(contextPath)) {
            requestUri = requestUri.substring(contextPath.length());
        }

        return requestUri.startsWith("/logout")
                || requestUri.startsWith("/zero-trust")
                || requestUri.startsWith("/api/aiam/sse/zero-trust")
                || requestUri.startsWith("/api/aiam/zero-trust")
                || requestUri.startsWith("/.well-known/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        /*boolean isBlocked = hasAuthority(auth, ZeroTrustAction.BLOCK.getGrantedAuthority());
        boolean isEscalated = hasAuthority(auth, ZeroTrustAction.ESCALATE.getGrantedAuthority());
        boolean isPendingAnalysis = hasAuthority(auth, ZeroTrustAction.PENDING_ANALYSIS.getGrantedAuthority());

        if (!isBlocked && !isEscalated && !isPendingAnalysis) {
            filterChain.doFilter(request, response);
            return;
        }*/

        String userId = extractUserId(auth);
        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
        ZeroTrustAction currentAction = actionRedisRepository.getCurrentAction(userId, contextBindingHash);

        if (currentAction != ZeroTrustAction.BLOCK
                && currentAction != ZeroTrustAction.ESCALATE
                && currentAction != ZeroTrustAction.PENDING_ANALYSIS) {
            filterChain.doFilter(request, response);
            return;
        }

        String requestUri = resolveRequestUri(request);

        switch (currentAction) {
            case BLOCK -> handleBlockWithMfa(request, response, filterChain, auth, userId, requestUri);
            case ESCALATE -> handleEscalate(request, response, userId);
            case PENDING_ANALYSIS -> handlePendingAnalysis(request, response, filterChain, userId);
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
                log.error("[ZeroTrustAccessControlFilter] BLOCK MFA attempts exhausted, denying MFA: userId={}", userId);
                handleBlocked(request, response, userId);
                return;
            }

            if (isMfaRelatedPath(requestUri)) {
                filterChain.doFilter(request, response);
                return;
            }

            if (challengeMfaInitializer != null) {
                initializeBlockMfa(request, response, auth, userId);
                return;
            }
        }

        handleBlocked(request, response, userId);
    }

    private boolean isBlockMfaPending(String userId) {
        return actionRedisRepository.isBlockMfaPending(userId);
    }

    private boolean isMfaRelatedPath(String requestUri) {
        if (requestUri.startsWith("/mfa/")
                || requestUri.startsWith("/api/mfa/")
                || requestUri.startsWith("/webauthn/")
                || requestUri.startsWith("/login/mfa-")) {
            return true;
        }
        // Check against dynamically configured MFA URLs from all flows (urlPrefix support)
        if (mfaFlowUrlRegistry != null) {
            Set<String> allFlowUrls = mfaFlowUrlRegistry.getAllMfaPageUrls();
            for (String mfaUrl : allFlowUrls) {
                if (requestUri.startsWith(mfaUrl) || requestUri.equals(mfaUrl)) {
                    return true;
                }
            }
        }
        if (authUrlProvider != null) {
            Set<String> mfaPageUrls = authUrlProvider.getMfaPageUrls();
            for (String mfaUrl : mfaPageUrls) {
                if (requestUri.startsWith(mfaUrl) || requestUri.equals(mfaUrl)) {
                    return true;
                }
            }
        }
        return false;
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
        return authUrlProvider;
    }

    private String buildMfaPageUrl(FactorContext context, HttpServletRequest request) {
        if (authUrlProvider == null) {
            return request.getContextPath() + "/mfa/select-factor";
        }

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

        String redirectUrl = request.getContextPath() + "/zero-trust/blocked";

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
                                String userId) throws IOException {

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

        promoteEscalateToBlock(userId, request, response);
    }

    private void respondWithReviewInProgress(HttpServletRequest request,
                                             HttpServletResponse response) throws IOException {

        String returnUrl = URLEncoder.encode(request.getRequestURI(), StandardCharsets.UTF_8);
        String redirectUrl = request.getContextPath()
                + "/zero-trust/analysis-pending?returnUrl=" + returnUrl;

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
                                        HttpServletResponse response) throws IOException {
        try {
            ZeroTrustAction currentAction = actionRedisRepository.getActionFromHash(userId);
            if (currentAction == ZeroTrustAction.BLOCK) {
                handleBlocked(request, response, userId);
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

            if (blockedUserRecorder != null) {
                blockedUserRecorder.recordBlock(
                        requestId, userId, username,
                        1.0, 0.0,
                        "Auto-promoted from ESCALATE: TTL expired without resolution",
                        request.getRemoteAddr(),
                        request.getHeader("User-Agent"));
            }

            log.error("[ZeroTrustAccessControlFilter] ESCALATE promoted to BLOCK: userId={}", userId);
        } catch (Exception e) {
            log.error("[ZeroTrustAccessControlFilter] Failed to promote ESCALATE to BLOCK: userId={}", userId, e);
        }

        handleBlocked(request, response, userId);
    }

    private void handlePendingAnalysis(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain filterChain,
                                        String userId) throws ServletException, IOException {
        if (blockingDecisionRegistry == null) {
            filterChain.doFilter(request, response);
            return;
        }

        BlockableResponseWrapper wrapper = new BlockableResponseWrapper(
                response, blockingDecisionRegistry, userId);
        try {
            filterChain.doFilter(request, wrapper);
        } catch (IOException e) {
            if (blockingDecisionRegistry.isBlocked(userId)) {
                log.error("[ZeroTrustAccessControlFilter] Response aborted for blocked user: userId={}", userId);
                sendBlockedResponseIfPossible(response, request);
                blockingDecisionRegistry.registerUnblock(userId);
                return;
            }
            throw e;
        } catch (ResponseBlockedException e) {
            log.error("[ZeroTrustAccessControlFilter] Response aborted for blocked user: userId={}", userId);
            sendBlockedResponseIfPossible(response, request);
            blockingDecisionRegistry.registerUnblock(userId);
            return;
        }
    }

    private void sendBlockedResponseIfPossible(HttpServletResponse response, HttpServletRequest request) {
        if (!response.isCommitted()) {
            try {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().write(
                        "{\"error\":\"RESPONSE_BLOCKED\",\"message\":\"Response terminated by AI security decision\",\"redirectUrl\":\"/zero-trust/blocked\"}");
                response.getWriter().flush();
            } catch (Exception ex) {
                log.error("[ZeroTrustAccessControlFilter] Failed to send blocked response JSON", ex);
            }
        }
    }

    private String resolveRequestUri(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (StringUtils.hasText(contextPath)) {
            requestUri = requestUri.substring(contextPath.length());
        }
        return requestUri;
    }

    private boolean hasAuthority(Authentication auth, String authority) {
        if (auth.getAuthorities() == null) {
            return false;
        }
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority::equals);
    }

    private String extractUserId(Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return "unknown";
        }
        return auth.getName();
    }
}
