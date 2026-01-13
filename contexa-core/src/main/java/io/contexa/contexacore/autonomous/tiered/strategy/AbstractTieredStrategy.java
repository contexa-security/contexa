package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacore.autonomous.config.FeedbackConstants;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
// AI Native v4.0: HCADVectorIntegrationService import 제거 (클래스 삭제됨)
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tiered Strategy 추상 기반 클래스
 *
 * AI Native v5.1.0: 2-Tier 구조 (Layer1 Contextual + Layer2 Expert)
 * Layer1/Layer2 전략의 공통 기능을 제공합니다:
 * - Cold→Hot Path 동기화
 * - Hot Path 피드백
 * - 공통 유틸리티 메서드
 *
 * 주의사항:
 * - 기존 Layer 클래스의 모든 기능 유지
 * - 공통 기능만 추출하여 제공
 * - 각 Layer의 독립성 보장
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
public abstract class AbstractTieredStrategy implements ThreatEvaluationStrategy {


    protected String getUserId(SecurityEvent event) {
        return event.getUserId() != null ?
            event.getUserId() : FeedbackConstants.DEFAULT_USER_ID;
    }

    protected abstract String getLayerName();

    @Override
    public String getStrategyName() {
        return getLayerName();
    }

    /**
     * LLM 응답에서 JSON 객체 추출
     *
     * LLM 응답은 종종 JSON 앞뒤에 텍스트를 포함합니다.
     * 이 메서드는 첫 번째 '{' 와 마지막 '}' 사이의 JSON 객체를 추출합니다.
     *
     * @param response LLM 응답 문자열
     * @return 추출된 JSON 문자열, 또는 원본 응답 (JSON 없는 경우)
     */
    protected String extractJsonObject(String response) {
        if (response == null || response.isEmpty()) {
            return "{}";
        }

        int startIndex = response.indexOf('{');
        if (startIndex == -1) {
            return response;
        }

        // AI Native v4.2.0: 첫 번째 완전한 JSON 객체만 추출 (balanced braces)
        // 다중 JSON이 있는 경우 첫 번째만 반환
        int braceCount = 0;
        int endIndex = -1;
        boolean inString = false;
        boolean escaped = false;

        for (int i = startIndex; i < response.length(); i++) {
            char c = response.charAt(i);

            if (escaped) {
                escaped = false;
                continue;
            }

            if (c == '\\') {
                escaped = true;
                continue;
            }

            if (c == '"') {
                inString = !inString;
                continue;
            }

            if (!inString) {
                if (c == '{') {
                    braceCount++;
                } else if (c == '}') {
                    braceCount--;
                    if (braceCount == 0) {
                        endIndex = i;
                        break;
                    }
                }
            }
        }

        if (endIndex != -1) {
            return response.substring(startIndex, endIndex + 1);
        }

        // fallback: 기존 로직 (마지막 } 사용)
        endIndex = response.lastIndexOf('}');
        if (endIndex > startIndex) {
            return response.substring(startIndex, endIndex + 1);
        }

        return response;
    }

    /**
     * 문자열 action을 SecurityDecision.Action으로 매핑 (AI Native v3.3.0)
     *
     * 공통 매핑 로직:
     * - ALLOW(A): 안전한 요청
     * - BLOCK(B): 극고위험군 (즉시 차단)
     * - CHALLENGE(C): 고위험군 (MFA 인증 요구)
     * - ESCALATE(E): 상위 Layer로 에스컬레이션
     *
     * Deprecated Actions (v3.3.0):
     * - INVESTIGATE(I): deprecated -> ESCALATE로 변환 (경고 로그)
     * - MONITOR(M): deprecated -> ESCALATE로 변환 (경고 로그)
     *
     * @param action LLM이 반환한 action 문자열
     * @return SecurityDecision.Action enum
     */
    protected SecurityDecision.Action mapStringToAction(String action) {
        if (action == null) return SecurityDecision.Action.ESCALATE;

        String upperAction = action.toUpperCase().trim();

        // Deprecated action 감지 및 경고 로그
        if ("INVESTIGATE".equals(upperAction) || "I".equals(upperAction)) {
            log.warn("[{}][AI Native v3.3.0] Deprecated action 'INVESTIGATE' detected. " +
                    "Converting to ESCALATE. Please update LLM prompt to use 4-action system: " +
                    "ALLOW, BLOCK, CHALLENGE, ESCALATE", getLayerName());
            return SecurityDecision.Action.ESCALATE;
        }
        if ("MONITOR".equals(upperAction) || "M".equals(upperAction)) {
            log.warn("[{}][AI Native v3.3.0] Deprecated action 'MONITOR' detected. " +
                    "Converting to ESCALATE. Please update LLM prompt to use 4-action system: " +
                    "ALLOW, BLOCK, CHALLENGE, ESCALATE", getLayerName());
            return SecurityDecision.Action.ESCALATE;
        }

        return switch (upperAction) {
            case "ALLOW", "A" -> SecurityDecision.Action.ALLOW;
            case "BLOCK", "B" -> SecurityDecision.Action.BLOCK;
            case "CHALLENGE", "C" -> SecurityDecision.Action.CHALLENGE;
            default -> {
                if (!"ESCALATE".equals(upperAction) && !"E".equals(upperAction)) {
                    log.warn("[{}][AI Native] Unknown action '{}' detected. Converting to ESCALATE",
                            getLayerName(), action);
                }
                yield SecurityDecision.Action.ESCALATE;
            }
        };
    }

    // AI Native v6.0: isValidAction() 메서드 삭제 (Dead Code)
    // - Layer1/Layer2에서 호출되지 않음
    // - mapStringToAction()이 유효하지 않은 action을 ESCALATE로 변환하므로 별도 검증 불필요

    // ========================================================================
    // AI Native v6.0: 공통 응답 검증 및 메타데이터 메서드
    // ========================================================================

    /**
     * LLM 응답의 riskScore, confidence 검증 및 NaN 변환
     *
     * AI Native 원칙:
     * - null인 경우 NaN으로 변환 (플랫폼이 임의 값 설정 금지)
     * - LLM이 판단하지 않은 것을 명시적으로 표현
     *
     * @param riskScore LLM이 반환한 riskScore (null 가능)
     * @param confidence LLM이 반환한 confidence (null 가능)
     * @return [0]: 검증된 riskScore, [1]: 검증된 confidence (null이면 NaN)
     */
    protected double[] validateResponseBase(Double riskScore, Double confidence) {
        double validatedRiskScore = (riskScore != null) ? riskScore : Double.NaN;
        double validatedConfidence = (confidence != null) ? confidence : Double.NaN;

        if (riskScore == null) {
            log.warn("[{}][AI Native] LLM이 riskScore 미반환 (가공 없이 NaN 사용)", getLayerName());
        }
        if (confidence == null) {
            log.warn("[{}][AI Native] LLM이 confidence 미반환 (가공 없이 NaN 사용)", getLayerName());
        }

        return new double[]{validatedRiskScore, validatedConfidence};
    }

    /**
     * 벡터 저장용 공통 메타데이터 생성
     *
     * AI Native 원칙:
     * - null인 경우 필드 생략 (LLM이 "unknown"을 실제 값으로 오해 방지)
     * - NaN인 경우 필드 생략 (LLM이 -1.0을 낮은 값으로 오해 방지)
     *
     * @param event SecurityEvent
     * @param decision SecurityDecision
     * @param documentType 문서 유형 문자열
     * @return 메타데이터 Map
     */
    protected Map<String, Object> buildBaseMetadata(SecurityEvent event, SecurityDecision decision, String documentType) {
        Map<String, Object> metadata = new HashMap<>();

        // 필수 공통 metadata
        metadata.put("documentType", documentType);
        // AI Native v6.0 Critical: 이벤트 발생 시간 사용 (저장 시간 X)
        // - RAG 검색 시 시간 패턴 분석을 위해 이벤트 실제 발생 시간 필요
        // - 저장 시간 사용 시 과거 이벤트가 "방금 발생"으로 잘못 인식됨
        String eventTimestamp = event.getTimestamp() != null
            ? event.getTimestamp().toString()
            : LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        metadata.put("timestamp", eventTimestamp);

        // SecurityEvent 정보 - AI Native: null인 경우 필드 생략
        if (event.getEventId() != null) {
            metadata.put("eventId", event.getEventId());
        }
        if (event.getUserId() != null) {
            metadata.put("userId", event.getUserId());
        }
        if (event.getSourceIp() != null) {
            metadata.put("sourceIp", event.getSourceIp());
        }
        if (event.getSessionId() != null) {
            metadata.put("sessionId", event.getSessionId());
        }

        // AI Native v6.7: riskScore, confidence 제거 (순환 로직 방지)
        // LLM 결과가 다음 분석에 영향을 미치면 독립적 분석 불가
        // action만 저장하여 다음 분석에서 과거 결정 참조
        if (decision.getAction() != null) {
            metadata.put("action", decision.getAction().name());
        }
        if (decision.getThreatCategory() != null) {
            metadata.put("threatCategory", decision.getThreatCategory());
        }

        return metadata;
    }

    // AI Native v6.0: buildBaseSessionContext(), enrichSessionContextFromRedis() 메서드 삭제 (Dead Code)
    // - Layer1/Layer2에서 호출되지 않음
    // - 각 Layer가 자체 buildSessionContext() 구현 사용:
    //   - Layer1: Caffeine 캐시 + addEvent() 호출 + 캐시 저장
    //   - Layer2: 캐시 없이 매번 새로 구축 + Redis 직접 보강
    // - 공통화 시도했으나 Layer별 특화 로직이 많아 통합 불가

    // ========================================================================
    // AI Native v6.0: 공통 행동 분석 메서드
    // ========================================================================

    /**
     * 유사 이벤트 검색 (Layer별 구현)
     *
     * 각 Layer에서 자체 벡터 서비스 및 폴백 로직을 구현합니다.
     * - Layer1: behaviorVectorService 사용, Redis SCAN 폴백
     * - Layer2: behaviorVectorService 사용, 빈 리스트 폴백
     *
     * @param event SecurityEvent
     * @return 유사 이벤트 목록 (없으면 빈 리스트)
     */
    protected abstract List<String> findSimilarEventsForLayer(SecurityEvent event);

    /**
     * 행동 패턴 분석 (공통 로직)
     *
     * 유사 이벤트 검색과 Baseline 컨텍스트 조회를 수행합니다.
     *
     * Zero Trust 원칙:
     * - 서비스 상태를 명시적으로 LLM에게 전달
     * - userId null은 시스템 오류로 처리
     * - 서비스 불가 시 [SERVICE_UNAVAILABLE] 마커 사용
     *
     * @param event SecurityEvent
     * @param baselineLearningService Baseline 학습 서비스 (null 가능)
     * @return 분석된 BaseBehaviorAnalysis
     */
    protected BaseBehaviorAnalysis analyzeBehaviorPatternsBase(SecurityEvent event,
                                                                 BaselineLearningService baselineLearningService) {
        BaseBehaviorAnalysis analysis = new BaseBehaviorAnalysis();
        String userId = event.getUserId();

        // 유사 이벤트 조회 (Layer별 구현)
        // AI Native: 빈 리스트는 그대로 유지, 마커 생성 금지
        List<String> similarEvents = findSimilarEventsForLayer(event);
        analysis.setSimilarEvents(similarEvents);

        // Zero Trust: 서비스 상태를 명시적으로 LLM에게 전달
        if (baselineLearningService == null) {
            analysis.setBaselineContext("[SERVICE_UNAVAILABLE] Baseline learning service not configured");
            analysis.setBaselineEstablished(false);
        } else if (userId == null) {
            // 인증 사용자 전용 플랫폼 - userId null은 시스템 오류
            log.error("[{}][SYSTEM_ERROR] userId is null - authentication system failure", getLayerName());
            analysis.setBaselineContext("[SYSTEM_ERROR] Authentication failure - userId unavailable. " +
                "This should not happen in authenticated platform. Recommend ESCALATE.");
            analysis.setBaselineEstablished(false);
        } else {
            try {
                String baselineContext = baselineLearningService.buildBaselinePromptContext(userId, event);

                if (baselineContext == null || baselineContext.isEmpty()) {
                    analysis.setBaselineContext("[NO_DATA] Baseline service returned empty response");
                } else {
                    analysis.setBaselineContext(baselineContext);
                    log.debug("[{}] Baseline context generated for user {}", getLayerName(), userId);
                }

                // Baseline 존재 여부 확인
                analysis.setBaselineEstablished(baselineLearningService.getBaseline(userId) != null);

            } catch (Exception e) {
                log.warn("[{}] Baseline service error for user {}: {}", getLayerName(), userId, e.getMessage());
                analysis.setBaselineContext("[SERVICE_ERROR] Baseline service error: " + e.getMessage());
                analysis.setBaselineEstablished(false);
            }
        }

        return analysis;
    }

    // ========================================================================
    // AI Native v6.0: Zero Trust 세션 보안 메서드
    // ========================================================================

    /**
     * Zero Trust: 세션 컨텍스트 변경 감지 (세션 하이재킹 탐지)
     *
     * 캐시된 세션과 현재 이벤트의 컨텍스트를 비교하여
     * IP 주소 또는 User-Agent 변경을 감지합니다.
     *
     * 탐지 항목:
     * 1. IP 주소 변경 - 세션 탈취 가능성
     * 2. User-Agent 변경 - 세션 탈취 또는 프록시 변경 가능성
     *
     * @param cached 캐시된 BaseSessionContext (또는 하위 클래스)
     * @param event 현재 SecurityEvent
     * @return 컨텍스트 변경 시 true (캐시 무효화 필요)
     */
    protected boolean isSessionContextChanged(BaseSessionContext cached, SecurityEvent event) {
        if (cached == null || event == null) {
            return false;
        }

        // 1. IP 주소 변경 감지
        String cachedIp = cached.getIpAddress();
        String eventIp = event.getSourceIp();
        if (cachedIp != null && eventIp != null && !cachedIp.equals(eventIp)) {
            log.warn("[{}][Zero Trust] IP changed: {} -> {}", getLayerName(), cachedIp, eventIp);
            return true;
        }

        // 2. User-Agent 변경 감지 (metadata에서 추출)
        if (event.getMetadata() != null && cached.getUserAgent() != null) {
            Object userAgentObj = event.getMetadata().get("userAgent");
            if (userAgentObj != null) {
                String eventUserAgent = userAgentObj.toString();
                String cachedUserAgent = cached.getUserAgent();
                // User-Agent가 완전히 다른 경우 세션 하이재킹 가능성
                if (!cachedUserAgent.equals(eventUserAgent)) {
                    // 브라우저 업데이트로 인한 minor version 변경은 허용
                    // 완전히 다른 User-Agent만 경고
                    if (!isSimilarUserAgent(cachedUserAgent, eventUserAgent)) {
                        log.warn("[{}][Zero Trust] User-Agent changed: {} -> {}",
                            getLayerName(),
                            cachedUserAgent.length() > 50 ? cachedUserAgent.substring(0, 50) + "..." : cachedUserAgent,
                            eventUserAgent.length() > 50 ? eventUserAgent.substring(0, 50) + "..." : eventUserAgent);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * User-Agent 유사도 검증
     *
     * 브라우저/OS 메이저 버전이 동일하면 유사하다고 판단합니다.
     * 마이너 버전 업데이트로 인한 User-Agent 변경은 정상으로 처리합니다.
     *
     * @param cached 캐시된 User-Agent
     * @param current 현재 User-Agent
     * @return 유사하면 true
     */
    protected boolean isSimilarUserAgent(String cached, String current) {
        if (cached == null || current == null) {
            return false;
        }

        // 브라우저 엔진 키워드 비교 (Chrome, Firefox, Safari, Edge 등)
        String[] browserKeywords = {"Chrome", "Firefox", "Safari", "Edge", "Opera", "MSIE", "Trident"};
        String cachedBrowser = null;
        String currentBrowser = null;

        for (String browser : browserKeywords) {
            if (cached.contains(browser)) {
                cachedBrowser = browser;
            }
            if (current.contains(browser)) {
                currentBrowser = browser;
            }
        }

        // 브라우저가 다르면 세션 하이재킹 가능성
        if (cachedBrowser == null || currentBrowser == null) {
            return false;
        }
        if (!cachedBrowser.equals(currentBrowser)) {
            return false;
        }

        // 같은 브라우저이고 OS 키워드가 동일하면 유사
        String[] osKeywords = {"Windows", "Mac OS", "Linux", "Android", "iOS", "iPhone", "iPad"};
        String cachedOs = null;
        String currentOs = null;

        for (String os : osKeywords) {
            if (cached.contains(os)) {
                cachedOs = os;
            }
            if (current.contains(os)) {
                currentOs = os;
            }
        }

        // OS가 다르면 세션 하이재킹 가능성
        if (cachedOs != null && currentOs != null && !cachedOs.equals(currentOs)) {
            return false;
        }

        return true;
    }

    // AI Native v6.0: isIpChanged() 메서드 삭제 (Dead Code)
    // - Layer1/Layer2에서 호출되지 않음
    // - isSessionContextChanged()가 IP + User-Agent 둘 다 검사하므로 별도 IP-only 메서드 불필요

    /**
     * AI Native v6.0: Redis 기반 세션 컨텍스트 변경 감지 (세션 하이재킹 탐지)
     *
     * Layer2처럼 캐시 없이 Redis에서 이전 세션 정보를 조회하여 비교합니다.
     * IP 주소 또는 User-Agent 변경을 감지합니다.
     *
     * @param sessionId 세션 ID
     * @param currentIp 현재 IP 주소
     * @param currentUserAgent 현재 User-Agent
     * @param redisTemplate Redis 템플릿
     * @return 컨텍스트 변경 시 true (세션 하이재킹 가능성)
     */
    protected boolean isSessionContextChangedFromRedis(String sessionId, String currentIp,
            String currentUserAgent, RedisTemplate<String, Object> redisTemplate) {
        if (sessionId == null || redisTemplate == null) {
            return false;
        }

        try {
            // Redis에서 이전 세션 메타데이터 조회
            String redisKey = ZeroTrustRedisKeys.sessionMetadata(sessionId);
            Map<Object, Object> cachedData = redisTemplate.opsForHash().entries(redisKey);

            if (cachedData.isEmpty()) {
                return false;  // 이전 세션 정보 없음 (신규 세션)
            }

            // 1. IP 주소 변경 감지
            Object cachedIpObj = cachedData.get("ipAddress");
            if (cachedIpObj != null && currentIp != null) {
                String cachedIp = cachedIpObj.toString();
                if (!cachedIp.equals(currentIp)) {
                    log.warn("[{}][Zero Trust] IP changed: {} -> {}", getLayerName(), cachedIp, currentIp);
                    return true;
                }
            }

            // 2. User-Agent 변경 감지
            Object cachedUserAgentObj = cachedData.get("userAgent");
            if (cachedUserAgentObj != null && currentUserAgent != null) {
                String cachedUserAgent = cachedUserAgentObj.toString();
                if (!cachedUserAgent.equals(currentUserAgent)) {
                    // 브라우저/OS 메이저 변경만 탐지 (마이너 버전 변경은 허용)
                    if (!isSimilarUserAgent(cachedUserAgent, currentUserAgent)) {
                        log.warn("[{}][Zero Trust] User-Agent changed: {} -> {}",
                            getLayerName(),
                            cachedUserAgent.length() > 50 ? cachedUserAgent.substring(0, 50) + "..." : cachedUserAgent,
                            currentUserAgent.length() > 50 ? currentUserAgent.substring(0, 50) + "..." : currentUserAgent);
                        return true;
                    }
                }
            }

            return false;
        } catch (Exception e) {
            log.debug("[{}] Session context change detection failed: {}", getLayerName(), e.getMessage());
            return false;
        }
    }

    // ========================================================================
    // AI Native v6.0: 공통 RAG 검색 메서드
    // ========================================================================

    /**
     * 벡터 스토어에서 관련 컨텍스트 검색 (공통 로직)
     *
     * AI Native 원칙:
     * - 빈 쿼리 시 무의미한 기본값 대신 검색 스킵
     * - BEHAVIOR 타입 문서만 검색
     * - 검색 실패 시 빈 리스트 반환 (LLM 분석은 계속 진행)
     *
     * @param event SecurityEvent
     * @param unifiedVectorService 벡터 서비스 (null이면 빈 리스트 반환)
     * @param eventEnricher 이벤트 보강 서비스
     * @param topK 검색할 최대 문서 수
     * @param similarityThreshold 유사도 임계값
     * @return 검색된 문서 리스트 (없으면 빈 리스트)
     */
    protected List<Document> searchRelatedContextBase(SecurityEvent event,
                                                       UnifiedVectorService unifiedVectorService,
                                                       SecurityEventEnricher eventEnricher,
                                                       int topK,
                                                       double similarityThreshold) {
        if (unifiedVectorService == null) {
            return java.util.Collections.emptyList();
        }

        try {
            // 검색 쿼리 빌드
            StringBuilder queryBuilder = new StringBuilder();

            // 1. 이벤트 설명 (가장 중요한 검색 키워드)
            if (event.getDescription() != null && !event.getDescription().isEmpty()) {
                queryBuilder.append(event.getDescription()).append(" ");
            }

            // 2. 요청 경로 (targetResource)
            String targetResource = eventEnricher.getTargetResource(event).orElse(null);
            if (targetResource != null && !targetResource.isEmpty()) {
                queryBuilder.append(targetResource).append(" ");
            }

            // AI Native v6.0: httpMethod 제거 - LLM 분석에 불필요 (Description/경로에서 유추 가능)

            // 3. 사용자 ID (보조 정보)
            if (event.getUserId() != null && !event.getUserId().equals("unknown")) {
                queryBuilder.append("user:").append(event.getUserId()).append(" ");
            }

            // 4. 소스 IP (보조 정보)
            if (event.getSourceIp() != null) {
                queryBuilder.append("IP:").append(event.getSourceIp()).append(" ");
            }

            String query = queryBuilder.toString().trim();
            // AI Native: 빈 쿼리 시 무의미한 기본값 대신 검색 스킵
            if (query.isEmpty()) {
                log.debug("[{}][AI Native] Empty query, skipping vector search for event {}",
                    getLayerName(), event.getEventId());
                return java.util.Collections.emptyList();
            }

            // BEHAVIOR 타입 문서만 검색
            String documentTypeFilter = String.format("documentType == '%s'",
                VectorDocumentType.BEHAVIOR.getValue());

            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(topK)
                    .similarityThreshold(similarityThreshold)
                    .filterExpression(documentTypeFilter)
                    .build();

            List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);

            log.debug("[{}] RAG behavioral context search: {} documents found for event {}",
                getLayerName(), documents != null ? documents.size() : 0, event.getEventId());

            return documents != null ? documents : java.util.Collections.emptyList();

        } catch (Exception e) {
            log.debug("[{}] Vector store context search failed", getLayerName(), e);
            return java.util.Collections.emptyList();
        }
    }

    // ========================================================================
    // AI Native v6.0: 공통 세션 컨텍스트 기반 클래스
    // ========================================================================

    /**
     * 세션 컨텍스트 기본 클래스
     *
     * Layer1/Layer2 공통 세션 정보를 저장합니다.
     * 각 Layer에서 필요에 따라 확장하여 사용합니다.
     *
     * Zero Trust 원칙:
     * - 모든 필드는 null 허용 (LLM이 판단)
     * - "unknown" 기본값 사용 금지
     * - IP, sessionId는 세션 하이재킹 탐지에 활용
     */
    protected static class BaseSessionContext {
        protected String sessionId;
        protected String userId;
        protected String authMethod;
        protected LocalDateTime startTime;
        protected String ipAddress;
        protected String userAgent;  // AI Native v6.0: 세션 하이재킹 탐지용
        protected List<String> recentActions = new ArrayList<>();
        protected int accessFrequency = 0;

        /**
         * 세션 유효성 검증
         * @return startTime이 설정되어 있으면 true
         */
        public boolean isValid() {
            return startTime != null;
        }

        /**
         * 세션 지속 시간 (분) 계산
         * @return 세션 시작부터 현재까지 분 단위, startTime이 null이면 0
         */
        public long getSessionDuration() {
            if (startTime == null) return 0;
            return Duration.between(startTime, LocalDateTime.now()).toMinutes();
        }

        // Getter/Setter - AI Native: null 그대로 반환 (기본값 금지)
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getAuthMethod() { return authMethod; }
        public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

        public LocalDateTime getStartTime() { return startTime; }
        public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }

        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

        public List<String> getRecentActions() { return recentActions; }
        public void setRecentActions(List<String> recentActions) { this.recentActions = recentActions; }

        public int getAccessFrequency() { return accessFrequency; }
        public void setAccessFrequency(int accessFrequency) { this.accessFrequency = accessFrequency; }
    }

    // ========================================================================
    // AI Native v6.0: 공통 행동 분석 기반 클래스
    // ========================================================================

    /**
     * 행동 분석 기본 클래스
     *
     * Layer1/Layer2 공통 행동 분석 정보를 저장합니다.
     * RAG 검색 결과와 Baseline 정보를 캡슐화합니다.
     *
     * AI Native 원칙:
     * - similarEvents: RAG에서 검색된 유사 이벤트 (없으면 빈 리스트)
     * - baselineContext: BaselineLearningService에서 반환된 Baseline 정보
     * - baselineEstablished: Baseline 존재 여부 (신규 사용자면 false)
     */
    protected static class BaseBehaviorAnalysis {
        protected List<String> similarEvents = new ArrayList<>();
        protected String baselineContext;
        protected boolean baselineEstablished;

        public List<String> getSimilarEvents() { return similarEvents; }
        public void setSimilarEvents(List<String> events) { this.similarEvents = events; }

        public String getBaselineContext() { return baselineContext; }
        public void setBaselineContext(String baselineContext) { this.baselineContext = baselineContext; }

        public boolean isBaselineEstablished() { return baselineEstablished; }
        public void setBaselineEstablished(boolean baselineEstablished) { this.baselineEstablished = baselineEstablished; }
    }
}