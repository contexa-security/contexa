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

/**
 * [템플릿 메서드 패턴] 웹 보안 표현식 루트
 * 
 * AbstractAISecurityExpressionRoot를 상속하여 공통 AI 기능을 활용하고,
 * 웹 보안 특화 기능을 제공합니다.
 * 
 * 상속받은 기능: assessContext(), getAttribute() 등의 AI 진단
 * 특화 기능: 웹 요청 컨텍스트 추출, hasIpAddress() 등의 웹 전용 기능
 */
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

        log.info("CustomWebSecurityExpressionRoot 초기화 완료 - 템플릿 메서드 패턴 적용");
    }

    /**
     * [웹 특화 기능] IP 주소 매칭
     * 
     * Spring Security의 표준 IP 매칭 기능을 제공합니다.
     */
    public boolean hasIpAddress(String ipAddress) {
        IpAddressMatcher matcher = new IpAddressMatcher(ipAddress);
        return matcher.matches(this.request);
    }

    // === 템플릿 메서드 패턴 구현 (추상 메서드 구현) ===

    @Override
    protected ContextExtractionResult extractCurrentContext() {
        try {
            // 웹 요청에서 정보 추출
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
            // 웹 요청 기반 해시 계산
            StringBuilder hashBuilder = new StringBuilder();
            hashBuilder.append(request.getRequestURI());
            hashBuilder.append("|");
            hashBuilder.append(request.getMethod());
            hashBuilder.append("|");
            hashBuilder.append(request.getRemoteAddr());
            hashBuilder.append("|");
            hashBuilder.append(System.currentTimeMillis() / 30000); // 30초 단위 캐시
            
            return String.valueOf(hashBuilder.toString().hashCode());
            
        } catch (Exception e) {
            return String.valueOf(System.currentTimeMillis() / 30000);
        }
    }

    // === 웹 요청 전용 컨텍스트 추출 메서드들 ===

    private String extractCurrentRequestIp() {
        try {
            // X-Forwarded-For 헤더 처리
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
            return request.getMethod(); // GET, POST, PUT, DELETE 등
        } catch (Exception e) {
            log.warn("액션 타입 추출 실패: {}", e.getMessage());
            return "UNKNOWN";
        }
    }

    // === 하위 호환성 메서드들 ===

    @Override
    protected String getRemoteIp() {
        return request.getRemoteAddr();
    }

    @Override
    protected String getCurrentActivityDescription() {
        return String.format("HTTP %s %s", request.getMethod(), request.getRequestURI());
    }

    /**
     * [하위 호환성] 기존 방식의 assessContext 오버라이드
     */
    @Override
    public TrustAssessment assessContext() {
        try {
            TrustAssessment assessment = super.assessContext();
            log.info("웹 보안 AI 평가 완료 - 점수: {}, 위험태그: {}",
                     assessment.score(), assessment.riskTags());
            
            return assessment;
            
        } catch (Exception e) {
            log.error("웹 보안 AI 신뢰도 평가 실패: {}", e.getMessage(), e);
            
            // 실패 시 보수적 기본값 생성
            TrustAssessment fallback = createFallbackTrustAssessment();
            this.authorizationContext.attributes().put("ai_assessment", fallback);
            
            return fallback;
        }
    }

    /**
     * (대안) AI 평가 결과에 직접 접근하기 위한 편의 메서드
     * 
     * SpEL 표현식 예시:
     * - #aiScore >= 0.7
     * - #aiScore < 0.3
     */
    public double getAiScore() {
        try {
            TrustAssessment assessment = assessContext();
            return assessment.score();
        } catch (Exception e) {
            log.warn("AI 점수 계산 실패, 기본값 반환: {}", e.getMessage());
            return 0.3; // 보수적 낮은 신뢰도
        }
    }

    /**
     * [하위 호환성] 실패 시 기본 TrustAssessment 생성
     */
    private TrustAssessment createFallbackTrustAssessment() {
        return new TrustAssessment(0.3, List.of("EVALUATION_FAILED", "LOW_TRUST"), "웹 보안 AI 평가 실패 - 보수적 정책 적용");
    }
}