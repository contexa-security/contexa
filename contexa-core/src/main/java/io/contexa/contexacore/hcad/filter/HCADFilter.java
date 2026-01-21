package io.contexa.contexacore.hcad.filter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

@Slf4j
public class HCADFilter extends OncePerRequestFilter {

    private final HCADAnalysisService hcadAnalysisService;

    private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    @Value("${hcad.enabled:true}")
    private boolean enabled;

    @Value("${hcad.cache.ttl-seconds:60}")
    private long cacheTtlSeconds;

    @Value("${hcad.cache.max-size:10000}")
    private long cacheMaxSize;

    @Value("${hcad.cache.enabled:true}")
    private boolean cacheEnabled;

    private Cache<String, HCADAnalysisResult> localCache;

    public HCADFilter(HCADAnalysisService hcadAnalysisService) {
        this.hcadAnalysisService = hcadAnalysisService;
    }

    @PostConstruct
    public void init() {
        
        this.localCache = Caffeine.newBuilder()
                .maximumSize(cacheMaxSize)
                .expireAfterWrite(cacheTtlSeconds, TimeUnit.SECONDS)
                .recordStats()  
                .build();

            }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = this.trustResolver.isAuthenticated(authentication);

        if (!enabled || !isAuthenticated) {
            filterChain.doFilter(request, response);
            return;
        }

        request.setAttribute("hcad.is_authenticated", isAuthenticated);

        try {
            
            String contextHash = generateContextHash(request);

            HCADAnalysisResult result = getCachedResult(contextHash);
            boolean fromCache = (result != null);

            if (result == null) {
                
                result = hcadAnalysisService.analyze(request, authentication);

                cacheResult(contextHash, result);
            }

            request.setAttribute("hcad.trust_score", result.getTrustScore());
            request.setAttribute("hcad.threat_type", result.getThreatType());
            request.setAttribute("hcad.threat_evidence", result.getThreatEvidence());
            request.setAttribute("hcad.is_anomaly", result.isAnomaly());
            request.setAttribute("hcad.risk_score", result.getAnomalyScore());
            request.setAttribute("hcad.action", result.getAction());  
            request.setAttribute("hcad.confidence", result.getConfidence());  
            request.setAttribute("hcad.from_cache", fromCache);

            if (result.getContext() != null) {
                request.setAttribute("hcad.is_new_session", result.getContext().getIsNewSession());
                request.setAttribute("hcad.is_new_user", result.getContext().getIsNewUser());
                request.setAttribute("hcad.is_new_device", result.getContext().getIsNewDevice());
                request.setAttribute("hcad.recent_request_count", result.getContext().getRecentRequestCount());
            }

            if (log.isDebugEnabled()) {
                            }

            String action = result.getAction();
            if ("BLOCK".equalsIgnoreCase(action) || "ESCALATE".equalsIgnoreCase(action)) {
                log.warn("[HCADFilter][AI Native] Security action: {} - userId: {}, riskScore: {}, threatType: {}",
                    action, result.getUserId(), String.format("%.3f", result.getAnomalyScore()), result.getThreatType());
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.error("[HCAD] 처리 중 오류 발생", e);
            
            filterChain.doFilter(request, response);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        
        String path = request.getRequestURI();
        return path.startsWith("/static/") ||
               path.startsWith("/css/") ||
               path.startsWith("/js/") ||
               path.startsWith("/images/") ||
               path.equals("/health") ||
               path.startsWith("/actuator/") ||
               path.startsWith("/api/admin/test/vectorstore");
    }

    private String generateContextHash(HttpServletRequest request) {
        String ip = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null) {
            userAgent = "unknown";
        }
        String path = request.getRequestURI();
        String method = request.getMethod();

        String contextString = ip + "|" + userAgent + "|" + path + "|" + method;

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(contextString.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            
            log.error("[HCADFilter] SHA-256 알고리즘 사용 불가", e);
            return String.valueOf(contextString.hashCode());
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip != null ? ip : "unknown";
    }

    private HCADAnalysisResult getCachedResult(String contextHash) {
        if (!cacheEnabled || localCache == null) {
            return null;
        }

        try {
            HCADAnalysisResult cached = localCache.getIfPresent(contextHash);
            if (cached != null && log.isDebugEnabled()) {
                            }
            return cached;
        } catch (Exception e) {
                    }
        return null;
    }

    private void cacheResult(String contextHash, HCADAnalysisResult result) {
        if (!cacheEnabled || localCache == null) {
            return;
        }

        try {
            localCache.put(contextHash, result);

            if (log.isDebugEnabled()) {
                            }
        } catch (Exception e) {
                    }
    }
}