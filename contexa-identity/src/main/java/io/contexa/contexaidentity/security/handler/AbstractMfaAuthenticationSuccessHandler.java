package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.hcad.domain.BaselineVector;
import io.contexa.contexacore.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.service.HCADContextExtractor;
import io.contexa.contexacore.hcad.service.HCADVectorIntegrationService;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.domain.dto.UserDto;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.token.dto.TokenPair;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.token.transport.TokenTransportResult;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * MFA 인증 성공 처리 핸들러
 *
 * 토큰 발급과 응답 처리를 담당하며, 사용자 커스텀 로직을 위한 확장점 제공
 */
@Slf4j
public abstract class AbstractMfaAuthenticationSuccessHandler implements PlatformAuthenticationSuccessHandler, ApplicationEventPublisherAware {

    private final TokenService tokenService;
    private final AuthResponseWriter responseWriter;
    private final MfaSessionRepository sessionRepository;
    private final MfaStateMachineIntegrator stateMachineIntegrator;
    private final RequestCache requestCache = new HttpSessionRequestCache();
    private PlatformAuthenticationSuccessHandler delegateHandler;
    private ApplicationEventPublisher eventPublisher;

    // HCAD 계산을 위한 의존성 (optional)
    private HCADContextExtractor hcadContextExtractor;
    private RedisTemplate<String, Object> redisTemplate;
    private HCADVectorIntegrationService hcadVectorService;

    @Value("${hcad.redis.key-prefix:hcad:baseline:v2:}")
    private String redisKeyPrefix = "hcad:baseline:v2:";

    protected AbstractMfaAuthenticationSuccessHandler(TokenService tokenService,
                                                      AuthResponseWriter responseWriter,
                                                      MfaSessionRepository sessionRepository,
                                                      MfaStateMachineIntegrator stateMachineIntegrator,
                                                      AuthContextProperties authContextProperties) {
        this.tokenService = tokenService;
        this.responseWriter = responseWriter;
        this.sessionRepository = sessionRepository;
        this.stateMachineIntegrator = stateMachineIntegrator;
    }

    public void setDelegateHandler(@Nullable PlatformAuthenticationSuccessHandler delegateHandler) {
        this.delegateHandler = delegateHandler;
        if (delegateHandler != null) {
            log.info("Delegate handler set: {}", delegateHandler.getClass().getName());
        }
    }
    
    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }

    /**
     * HCAD 계산 의존성 설정 (optional)
     */
    public void setHcadDependencies(HCADContextExtractor extractor,
                                    RedisTemplate<String, Object> redis,
                                    HCADVectorIntegrationService vectorService) {
        this.hcadContextExtractor = extractor;
        this.redisTemplate = redis;
        this.hcadVectorService = vectorService;
    }

    /**
     * 최종 인증 성공 처리 - 플랫폼 핵심 로직
     */
    protected final void handleFinalAuthenticationSuccess(HttpServletRequest request,
                                                          HttpServletResponse response,
                                                          Authentication finalAuthentication,
                                                          @Nullable FactorContext factorContext) throws IOException {

        if (response.isCommitted()) {
            log.warn("Response already committed for user: {}", ((UserDto)finalAuthentication.getPrincipal()).getUsername());
            return;
        }

        // 1. 토큰 생성 (request/response 직접 전달)
        String deviceId = factorContext != null ? (String) factorContext.getAttribute("deviceId") : null;
        TokenPair tokenPair = tokenService.createTokenPair(finalAuthentication, deviceId, request, response);
        String accessToken = tokenPair.getAccessToken();
        String refreshToken = tokenPair.getRefreshToken();

        // 2. 세션 정리
        if (factorContext != null && factorContext.getMfaSessionId() != null) {
            stateMachineIntegrator.releaseStateMachine(factorContext.getMfaSessionId());
            sessionRepository.removeSession(factorContext.getMfaSessionId(), request, response);
        }

        // 3. 토큰 전송 정보 준비
        TokenTransportResult transportResult = tokenService.prepareTokensForTransport(accessToken, refreshToken);

        // 4. 응답 데이터 구성
        Map<String, Object> responseData = new HashMap<>(transportResult.getBody());
        responseData.put("status", "MFA_COMPLETED");
        responseData.put("message", "인증이 완료되었습니다.");
        responseData.put("redirectUrl", determineTargetUrl(request, response, finalAuthentication));
        responseData.put("authentication", finalAuthentication);

        TokenTransportResult finalResult = TokenTransportResult.builder()
                .body(responseData)
                .cookiesToSet(transportResult.getCookiesToSet())
                .cookiesToRemove(transportResult.getCookiesToRemove())
                .headers(transportResult.getHeaders())
                .build();

        // 5. 위임 핸들러 호출
        if (delegateHandler != null && !response.isCommitted()) {
            try {
                delegateHandler.onAuthenticationSuccess(request, response, finalAuthentication, finalResult);
            } catch (Exception e) {
                log.error("Error in delegate handler", e);
            }
        }

        // 6. 하위 클래스 훅 호출
        if (!response.isCommitted()) {
            onFinalAuthenticationSuccess(request, response, finalAuthentication, finalResult);
        }

        // 7. 플랫폼 기본 응답
        if (!response.isCommitted()) {
            processDefaultResponse(response, finalResult);
        }
        
        // 8. Zero Trust 이벤트 발행
        publishAuthenticationSuccessEvent(request, finalAuthentication, factorContext, finalResult);
    }

    /**
     * 하위 클래스 확장점
     */
    protected void onFinalAuthenticationSuccess(HttpServletRequest request,
                                                HttpServletResponse response,
                                                Authentication authentication,
                                                TokenTransportResult transportResult) throws IOException {
        // 하위 클래스에서 필요시 오버라이드
    }

    private void processDefaultResponse(HttpServletResponse response, TokenTransportResult result)
            throws IOException {
        // 쿠키 설정
        if (result.getCookiesToSet() != null) {
            for (ResponseCookie cookie : result.getCookiesToSet()) {
                response.addHeader("Set-Cookie", cookie.toString());
            }
        }

        // JSON 응답
        responseWriter.writeSuccessResponse(response, result.getBody(), HttpServletResponse.SC_OK);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
        if (savedRequest != null) {
            this.requestCache.removeRequest(request, response);
            return savedRequest.getRedirectUrl();
        }
        return request.getContextPath() + "/home";
    }
    
    /**
     * Zero Trust를 위한 인증 성공 이벤트 발행
     * 모든 성공한 인증을 AI가 실시간 분석하여 이상 패턴 감지
     */
    private void publishAuthenticationSuccessEvent(HttpServletRequest request,
                                                   Authentication authentication,
                                                   @Nullable FactorContext factorContext,
                                                   TokenTransportResult transportResult) {
        try {
            if (eventPublisher == null) {
                log.debug("ApplicationEventPublisher not available, skipping event publication");
                return;
            }
            
            UserDto userDto = (UserDto) authentication.getPrincipal();

            // 이벤트 빌더 생성
            AuthenticationSuccessEvent.AuthenticationSuccessEventBuilder builder = 
                AuthenticationSuccessEvent.builder()
                    .eventId(java.util.UUID.randomUUID().toString())
                    .userId(userDto.getUsername())  // Zero Trust를 위한 사용자 식별자 (username)
                    .username(userDto.getUsername())
                    .sessionId(request.getSession(false) != null ? request.getSession().getId() : null)
                    .eventTimestamp(java.time.LocalDateTime.now())
                    .sourceIp(extractClientIp(request))
                    .userAgent(request.getHeader("User-Agent"))
                    .authenticationType(factorContext != null && factorContext.isCompleted() ? "MFA" : "PRIMARY");
            
            // FactorContext 에서 추가 정보 추출
            if (factorContext != null) {
                builder.mfaCompleted(factorContext.isCompleted())
                       .deviceId((String) factorContext.getAttribute("deviceId"))
                       .mfaMethod(factorContext.getCurrentProcessingFactor() != null ? 
                                 factorContext.getCurrentProcessingFactor().toString() : null);
                
                // AI 위험 평가 정보
                Double aiRiskScore = (Double) factorContext.getAttribute("aiRiskScore");
                if (aiRiskScore != null) {
                    builder.trustScore(1.0 - aiRiskScore); // 위험 점수를 신뢰 점수로 변환
                }
                
                // 이상 징후 감지
                Boolean blocked = (Boolean) factorContext.getAttribute("blocked");
                builder.anomalyDetected(blocked != null && blocked);
                
                // 세션 컨텍스트
                Map<String, Object> sessionContext = new HashMap<>();
                sessionContext.put("mfaSessionId", factorContext.getMfaSessionId());
                sessionContext.put("currentState", factorContext.getCurrentState());
                sessionContext.put("registeredFactors", factorContext.getRegisteredMfaFactors());
                builder.sessionContext(sessionContext);
            }
            
            // 추가 메타데이터
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("requestPath", request.getRequestURI());
            metadata.put("httpMethod", request.getMethod());
            if (transportResult != null && transportResult.getBody() != null) {
                metadata.put("authenticationResult", transportResult.getBody().get("status"));
            }
            builder.metadata(metadata);

            // HCAD 유사도 계산 (인증 시점에 이상 탐지 수행)
            Double hcadSimilarity = calculateHCADSimilarity(request, authentication);
            builder.hcadSimilarityScore(hcadSimilarity);
            
            // 이벤트 발행
            AuthenticationSuccessEvent event = builder.build();
            eventPublisher.publishEvent(event);
            
            log.debug("Published authentication success event for user: {}, eventId: {}", 
                     userDto.getUsername(), event.getEventId());
            
        } catch (Exception e) {
            // 이벤트 발행 실패가 인증 프로세스를 중단시키지 않도록 예외 처리
            log.error("Failed to publish authentication success event", e);
        }
    }
    
    /**
     * 클라이언트 IP 추출 (프록시 고려)
     */
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

    /**
     * HCAD 유사도 계산
     *
     * HCADFilter는 인증 전 요청을 통과시키므로 (인증되지 않은 상태),
     * 인증 성공 시점에 직접 HCAD 분석을 수행하여 Zero Trust 원칙을 구현합니다.
     *
     * @return HCAD 유사도 점수 (0.0 ~ 1.0, 높을수록 정상) 또는 null (계산 실패 시)
     */
    private Double calculateHCADSimilarity(HttpServletRequest request, Authentication authentication) {
        try {
            // HCAD 의존성이 주입되지 않았으면 null 반환
            if (hcadContextExtractor == null || redisTemplate == null) {
                log.debug("[HCAD] Dependencies not available, skipping HCAD calculation");
                return null;
            }

            // 1. HCADContext 생성
            HCADContext context = hcadContextExtractor.extractContext(request, authentication);

            // 2. Redis에서 BaselineVector 조회
            String redisKey = redisKeyPrefix + context.getUserId();
            BaselineVector baseline = (BaselineVector) redisTemplate.opsForValue().get(redisKey);

            if (baseline == null) {
                // 기준선이 없으면 초기 기준선 생성
                baseline = BaselineVector.builder()
                    .userId(context.getUserId())
                    .confidence(0.0)
                    .updateCount(0L)
                    .lastUpdated(Instant.now())
                    .build();
            }

            // 3. 하이브리드 유사도 계산 (HCADFilter 로직과 동일)
            double baselineSimilarity = baseline.calculateSimilarity(context);
            double vectorSimilarity = baselineSimilarity;

            if (hcadVectorService != null) {
                try {
                    // 벡터 임베딩 생성 및 이상 점수 계산
                    float[] embedding = hcadVectorService.generateContextEmbedding(context);
                    double vectorAnomalyScore = hcadVectorService.calculateRealTimeAnomalyScore(
                        embedding,
                        context.getUserId()
                    );
                    vectorSimilarity = 1.0 - vectorAnomalyScore;

                    // 하이브리드: Baseline 60% + Vector 40%
                    double hybridSimilarity = (baselineSimilarity * 0.6) + (vectorSimilarity * 0.4);

                    log.info("[HCAD] Authentication HCAD calculated: userId={}, baseline={}, vector={}, hybrid={}",
                        context.getUserId(),
                        String.format("%.3f", baselineSimilarity),
                        String.format("%.3f", vectorSimilarity),
                        String.format("%.3f", hybridSimilarity));

                    return hybridSimilarity;

                } catch (Exception e) {
                    log.debug("[HCAD] Vector scoring failed, using baseline only", e);
                }
            }

            log.info("[HCAD] Authentication HCAD calculated (baseline only): userId={}, similarity={}",
                context.getUserId(), String.format("%.3f", baselineSimilarity));

            return baselineSimilarity;

        } catch (Exception e) {
            log.error("[HCAD] Failed to calculate HCAD similarity during authentication", e);
            // Zero Trust: 계산 실패 시 null 반환하여 후속 분석으로 위임
            return null;
        }
    }
}