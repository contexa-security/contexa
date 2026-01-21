package io.contexa.contexaiam.security.xacml.pdp.evaluation.url;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.AbstractAISecurityExpressionRoot;
import io.contexa.contexaiam.security.xacml.pip.attribute.AttributeInformationPoint;
import io.contexa.contexaiam.security.xacml.pip.context.AuthorizationContext;
import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacommon.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.util.List;

@Slf4j
public class CustomWebSecurityExpressionRoot extends AbstractAISecurityExpressionRoot {

    private final HttpServletRequest request;
    public CustomWebSecurityExpressionRoot(Authentication authentication, HttpServletRequest request,
                                           AttributeInformationPoint attributePIP,
                                           AICoreOperations aINativeProcessor,
                                           AuthorizationContext authorizationContext,
                                           AuditLogRepository auditLogRepository) {
        super(authentication, attributePIP, aINativeProcessor, authorizationContext, auditLogRepository);
        this.request = request;

            }

    public boolean hasIpAddress(String ipAddress) {
        IpAddressMatcher matcher = new IpAddressMatcher(ipAddress);
        return matcher.matches(this.request);
    }

    @Override
    protected ContextExtractionResult extractCurrentContext() {
        try {
            
            String remoteIp = extractCurrentRequestIp();
            String userAgent = extractCurrentRequestUserAgent();
            String resourceIdentifier = extractCurrentRequestResource();
            String actionType = extractCurrentRequestAction();
            
            return new ContextExtractionResult(remoteIp, userAgent, resourceIdentifier, actionType);
            
        } catch (Exception e) {
            log.warn("웹 컨텍스트 추출 실패: {}", e.getMessage());
            return new ContextExtractionResult("127.0.0.1", "unknown", "/", "GET");
        }
    }

    @Override
    protected String calculateContextHash() {
        try {
            
            StringBuilder hashBuilder = new StringBuilder();
            hashBuilder.append(request.getRequestURI());
            hashBuilder.append("|");
            hashBuilder.append(request.getMethod());
            hashBuilder.append("|");
            hashBuilder.append(extractCurrentRequestIp()); 
            hashBuilder.append("|");
            hashBuilder.append(System.currentTimeMillis() / 30000); 

            return String.valueOf(hashBuilder.toString().hashCode());

        } catch (Exception e) {
            return String.valueOf(System.currentTimeMillis() / 30000);
        }
    }

    private String extractCurrentRequestIp() {
        try {
            
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                return xForwardedFor.split(",")[0].trim();
            }
            
            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isEmpty()) {
                return xRealIp;
            }
            
            return request.getRemoteAddr();
        } catch (Exception e) {
            log.warn("IP 주소 추출 실패: {}", e.getMessage());
            return "127.0.0.1";
        }
    }

    private String extractCurrentRequestUserAgent() {
        try {
            String userAgent = request.getHeader("User-Agent");
            return userAgent != null ? userAgent : "Unknown";
        } catch (Exception e) {
            log.warn("User-Agent 추출 실패: {}", e.getMessage());
            return "Unknown";
        }
    }

    private String extractCurrentRequestResource() {
        try {
            String requestURI = request.getRequestURI();
            String queryString = request.getQueryString();
            
            if (queryString != null) {
                return requestURI + "?" + queryString;
            }
            return requestURI;
        } catch (Exception e) {
            log.warn("리소스 식별자 추출 실패: {}", e.getMessage());
            return "unknown-resource";
        }
    }

    private String extractCurrentRequestAction() {
        try {
            return request.getMethod(); 
        } catch (Exception e) {
            log.warn("액션 타입 추출 실패: {}", e.getMessage());
            return "UNKNOWN";
        }
    }

    @Override
    protected String getRemoteIp() {
        
        return extractCurrentRequestIp();
    }

    @Override
    protected String getCurrentActivityDescription() {
        return String.format("HTTP %s %s", request.getMethod(), request.getRequestURI());
    }

    @Override
    public TrustAssessment assessContext() {
        try {
            TrustAssessment assessment = super.assessContext();
                        
            return assessment;
            
        } catch (Exception e) {
            log.error("웹 보안 AI 신뢰도 평가 실패: {}", e.getMessage(), e);

            TrustAssessment fallback = createFallbackTrustAssessment();
            this.authorizationContext.attributes().put("ai_assessment", fallback);
            
            return fallback;
        }
    }

    public double getAiScore() {
        try {
            TrustAssessment assessment = assessContext();
            return assessment.score();
        } catch (Exception e) {
            log.warn("AI 점수 계산 실패, 기본값 반환: {}", e.getMessage());
            return 0.3; 
        }
    }

    private TrustAssessment createFallbackTrustAssessment() {
        return new TrustAssessment(0.3, List.of("EVALUATION_FAILED", "LOW_TRUST"), "웹 보안 AI 평가 실패 - 보수적 정책 적용");
    }

    @Override
    protected String getCurrentAction() {
        return extractCurrentRequestAction();
    }
}