package io.contexa.contexacore.autonomous.event.filter;

import io.contexa.contexacore.autonomous.event.decision.UnifiedEventPublishingDecisionEngine;
import io.contexa.contexacore.autonomous.event.domain.HttpRequestEvent;
import io.contexa.contexacore.autonomous.utils.UserIdentificationStrategy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.UUID;


@Slf4j
@RequiredArgsConstructor
public class SecurityEventPublishingFilter extends OncePerRequestFilter {

    private final ApplicationEventPublisher applicationEventPublisher;
    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private final UnifiedEventPublishingDecisionEngine unifiedDecisionEngine;
    
    

    @Value("${security.event.publishing.enabled:true}")
    private boolean eventPublishingEnabled;

    @Value("${security.event.publishing.anonymous.enabled:true}")
    private boolean anonymousEventPublishingEnabled;

    @Value("${security.event.publishing.exclude-uris:/actuator,/health,/metrics}")
    private String[] excludeUris;

    
    @Value("${security.allow-simulated-headers:false}")
    private boolean allowSimulatedHeaders;

    
    
    
    

    
    private static final String HCAD_IS_ANOMALY = "hcad.is_anomaly";
    private static final String HCAD_RISK_SCORE = "hcad.risk_score";
    private static final String HCAD_ACTION = "hcad.action";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        
        String path = request.getRequestURI();
        return path.startsWith("/actuator/") ||
               path.startsWith("/api/admin/test/vectorstore");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } finally {

            
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            Boolean hcadAuthCheck = (Boolean) request.getAttribute("hcad.is_authenticated");
            boolean isAuthenticated;
            if (hcadAuthCheck != null) {
                
                isAuthenticated = hcadAuthCheck;
                log.trace("[SecurityEventPublishingFilter] Reusing auth check from HCADFilter: isAuthenticated={}", isAuthenticated);
            } else {
                isAuthenticated = auth != null && trustResolver.isAuthenticated(auth);
                log.trace("[SecurityEventPublishingFilter] Direct auth check (HCADFilter bypassed): isAuthenticated={}", isAuthenticated);
            }

            if (eventPublishingEnabled || isAuthenticated) {

            }

        }
    }

    
    private void publishEventIfNeeded(HttpServletRequest request, HttpServletResponse response, Authentication auth) {
        try {
            
            if (shouldExcludeUri(request.getRequestURI())) {
                log.trace("[SecurityEventPublishingFilter] URI excluded from event publishing: {}", request.getRequestURI());
                return;
            }

            
            Boolean eventPublished = (Boolean) request.getAttribute("security.event.published");
            if (Boolean.TRUE.equals(eventPublished)) {
                log.debug("[SecurityEventPublishingFilter] Event already published by specific handler, skipping general event: uri={}",
                         request.getRequestURI());
                return;
            }

            
            boolean isAuthenticated = auth != null && trustResolver.isAuthenticated(auth);

            
            
            
            Boolean fromCache = (Boolean) request.getAttribute("hcad.from_cache");
            if (Boolean.TRUE.equals(fromCache) && !isAuthenticated) {
                
                log.debug("[SecurityEventPublishingFilter] Anonymous event skipped (cache hit): uri={}",
                         request.getRequestURI());
                return;
            }

            if (Boolean.TRUE.equals(fromCache) && isAuthenticated) {
                
                log.debug("[SecurityEventPublishingFilter][ZeroTrust] Authenticated user - publishing event despite cache hit: uri={}",
                         request.getRequestURI());
            }

            
            Boolean hcadIsAnomaly = (Boolean) request.getAttribute(HCAD_IS_ANOMALY);
            Double hcadRiskScore = (Double) request.getAttribute(HCAD_RISK_SCORE);
            String hcadAction = (String) request.getAttribute(HCAD_ACTION);

            
            String userId = "";
            UnifiedEventPublishingDecisionEngine.PublishingDecision decision = null;
            userId = UserIdentificationStrategy.getUserId(auth);
            
            decision = unifiedDecisionEngine.decideAuthenticated(request, auth, userId,
                                                                  hcadAction, hcadIsAnomaly, hcadRiskScore);
            if (!decision.isShouldPublish()) {
                log.debug("[SecurityEventPublishingFilter] Authenticated event skipped by AI: userId={}, {}",
                         userId, decision);
                return;
            }

            log.debug("[SecurityEventPublishingFilter] Authenticated event approved by AI: userId={}, {}",
                     userId, decision);

            
            Boolean isNewSession = (Boolean) request.getAttribute("hcad.is_new_session");
            Boolean isNewUser = (Boolean) request.getAttribute("hcad.is_new_user");
            Boolean isNewDevice = (Boolean) request.getAttribute("hcad.is_new_device");
            Integer recentRequestCount = (Integer) request.getAttribute("hcad.recent_request_count");

            HttpRequestEvent.HttpRequestEventBuilder eventBuilder = HttpRequestEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventTimestamp(LocalDateTime.now())
                .userId(userId)
                .sourceIp(extractClientIp(request))
                .userAgent(extractUserAgent(request))      
                .requestUri(request.getRequestURI())
                .httpMethod(request.getMethod())
                .statusCode(response.getStatus())
                .hcadIsAnomaly(hcadIsAnomaly)              
                .hcadAnomalyScore(hcadRiskScore)           
                .hcadAction(hcadAction)                    
                .authentication(auth)
                .isAnonymous(false)
                .eventTier(decision.getTier())
                .riskScore(decision.getRiskScore())
                .trustScore(decision.getTrustScore())
                
                .isNewSession(isNewSession)
                .isNewUser(isNewUser)
                .isNewDevice(isNewDevice)
                .recentRequestCount(recentRequestCount)
                
                .authMethod(extractAuthMethod(auth));

            HttpRequestEvent event = eventBuilder.build();

            
            long startTime = System.nanoTime();

            applicationEventPublisher.publishEvent(event);

            long duration = System.nanoTime() - startTime;

            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            

        log.debug("[SecurityEventPublishingFilter] Published HttpRequestEvent (AI Native): userId={}, uri={}, action={}, isAnomaly={}, Risk={:.3f}, Tier={}",
                 userId, request.getRequestURI(),
                 hcadAction, hcadIsAnomaly,
                 decision.getRiskScore(), decision.getTier());

        } catch (Exception e) {
            
            log.error("[SecurityEventPublishingFilter] Failed to publish HttpRequestEvent", e);
        }
    }

    
    private boolean shouldExcludeUri(String uri) {
        if (uri == null || excludeUris == null) {
            return false;
        }

        for (String excludePattern : excludeUris) {
            if (uri.startsWith(excludePattern.trim())) {
                return true;
            }
        }

        return false;
    }

    
    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    
    private String extractUserAgent(HttpServletRequest request) {
        
        if (allowSimulatedHeaders) {
            String simulated = request.getHeader("X-Simulated-User-Agent");
            if (simulated != null && !simulated.isEmpty()) {
                log.debug("[SecurityEventPublishingFilter] Using simulated User-Agent: {}", simulated);
                return simulated;
            }
        }

        
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "unknown";
    }

    
    private String extractAuthMethod(Authentication auth) {
        if (auth == null) {
            return null;
        }

        String className = auth.getClass().getSimpleName();

        
        if (className.contains("UsernamePassword")) {
            return "PASSWORD";
        }
        if (className.contains("OAuth2")) {
            return "OAUTH2";
        }
        if (className.contains("Jwt") || className.contains("JWT")) {
            return "JWT";
        }
        if (className.contains("Mfa") || className.contains("MFA")) {
            return "MFA";
        }
        if (className.contains("Remember")) {
            return "REMEMBER_ME";
        }
        if (className.contains("Anonymous")) {
            return "ANONYMOUS";
        }
        if (className.contains("PreAuthenticated")) {
            return "PRE_AUTH";
        }

        
        return className;
    }
}
