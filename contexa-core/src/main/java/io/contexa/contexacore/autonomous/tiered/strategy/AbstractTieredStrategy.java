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

    protected String extractJsonObject(String response) {
        if (response == null || response.isEmpty()) {
            return "{}";
        }

        int startIndex = response.indexOf('{');
        if (startIndex == -1) {
            return response;
        }

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

        // AI Native v8.5: Hour 정보 별도 저장 (시간대 패턴 분석용)
        // - timestamp 문자열에서 추출하기 어려우므로 별도 필드로 저장
        // - LLM이 RELATED CONTEXT에서 시간대 패턴을 쉽게 분석 가능
        if (event.getTimestamp() != null) {
            metadata.put("hour", event.getTimestamp().getHour());
        }

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

        // AI Native v7.1: userAgent 정보 추가 (디바이스 패턴 분석용)
        // LLM이 RELATED CONTEXT에서 이전 요청의 디바이스 정보를 볼 수 있도록 함
        if (event.getUserAgent() != null && !event.getUserAgent().isEmpty()) {
            metadata.put("userAgent", event.getUserAgent());
            // OS 정보 추출하여 저장 (LLM 분석 용이성)
            String userAgentOS = extractOSFromUserAgent(event.getUserAgent());
            if (userAgentOS != null) {
                metadata.put("userAgentOS", userAgentOS);
            }
        }

        // AI Native v7.0: action, riskScore, confidence 모두 제거 (순환 로직 방지)
        // LLM 결과(action 포함)가 다음 분석에 영향을 미치면 독립적 분석 불가
        // action 저장 제거: 이전 BLOCK/ALLOW가 다음 판단에 편향을 줄 수 있음
        // threatCategory만 유지 (위협 유형 분류는 참조용으로 허용)
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
        // AI Native v8.8: "Mac OS" → "Mac" (extractUASignature 반환값과 일치)
        // AI Native v8.8: "ChromeOS" 추가 (extractUASignature에서 지원)
        // AI Native v8.8: "iPod" 추가 (iOS 디바이스 완전 지원)
        String[] osKeywords = {"Windows", "Mac", "Linux", "Android", "iOS", "iPhone", "iPad", "iPod", "ChromeOS"};
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
            // AI Native v8.6: Document-Query 형식 100% 통일 (Similarity 95%+ 목표)
            // Document Content: "User: admin, IP: 0:0:0:0:0:0:0:1, Path: /api/users"
            // Query: 동일한 형식으로 통일
            StringBuilder queryBuilder = new StringBuilder();

            // 1. User (검색 키 - Document와 일치)
            if (event.getUserId() != null && !event.getUserId().equals("unknown")) {
                queryBuilder.append("User: ").append(event.getUserId());
            }

            // 2. IP (검색 키 - Document와 일치)
            if (event.getSourceIp() != null) {
                if (queryBuilder.length() > 0) queryBuilder.append(", ");
                queryBuilder.append("IP: ").append(event.getSourceIp());
            }

            // 3. Path (검색 키 - Document와 일치, "Path: " 접두사 추가)
            String targetResource = eventEnricher.getTargetResource(event).orElse(null);
            if (targetResource != null && !targetResource.isEmpty()) {
                if (queryBuilder.length() > 0) queryBuilder.append(", ");
                queryBuilder.append("Path: ").append(targetResource);
            }

            // AI Native v8.9: OS 정보 추가 (Document Content와 일치 - 벡터 유사도 향상)
            // SecurityDecisionPostProcessor.buildBehaviorContent()와 동일한 형식 사용
            String currentOS = extractOSFromUserAgent(event.getUserAgent());
            if (currentOS != null && !"Desktop".equals(currentOS)) {
                if (queryBuilder.length() > 0) queryBuilder.append(", ");
                queryBuilder.append("OS: ").append(currentOS);
            }

            // AI Native v8.6: description 제거 (Document Content에 없음 -> Similarity 저하 원인)
            // AI Native v6.0: httpMethod 제거 - LLM 분석에 불필요

            String query = queryBuilder.toString().trim();
            // AI Native: 빈 쿼리 시 무의미한 기본값 대신 검색 스킵
            if (query.isEmpty()) {
                log.debug("[{}][AI Native] Empty query, skipping vector search for event {}",
                    getLayerName(), event.getEventId());
                return java.util.Collections.emptyList();
            }

            // AI Native v8.5: BEHAVIOR 타입 + userId 필터 (계정 격리 - CRITICAL)
            // userId 필터가 없으면 다른 사용자의 데이터가 LLM 분석에 포함되어
            // 정상 사용자와 공격자 구분이 불가능해짐
            String userId = event.getUserId();
            if (userId == null || userId.isEmpty() || "unknown".equals(userId)) {
                // AI Native v8.5: userId 없는 경우 검색 차단 (보안 강화)
                // 폴백 검색은 모든 사용자 데이터를 반환하여 계정 격리 실패 야기
                log.warn("[{}][AI Native v8.5] userId 없음 - RAG 검색 스킵 (계정 격리 보호)",
                    getLayerName());
                return java.util.Collections.emptyList();
            }

            String documentTypeFilter = String.format("documentType == '%s' && userId == '%s'",
                VectorDocumentType.BEHAVIOR.getValue(), userId);
            log.debug("[{}][AI Native v8.5] RAG search with userId filter: {}", getLayerName(), userId);

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

    // ========================================================================
    // AI Native v7.1: User-Agent OS 추출 유틸리티
    // ========================================================================

    /**
     * User-Agent에서 OS 정보 추출
     *
     * AI Native v7.1: LLM이 디바이스 패턴을 분석할 수 있도록
     * User-Agent에서 OS 정보를 추출하여 메타데이터에 저장합니다.
     *
     * @param userAgent User-Agent 문자열
     * @return OS 이름 (Android, iOS, Windows, Mac, Linux, ChromeOS, Mobile, Desktop)
     */
    protected String extractOSFromUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }

        // 모바일 OS 우선 검사 (Android가 Linux를 포함하므로)
        if (userAgent.contains("Android")) {
            return "Android";
        }
        // AI Native v8.8: iPod 추가 (드물지만 존재)
        if (userAgent.contains("iPhone") || userAgent.contains("iPad")
                || userAgent.contains("iPod") || userAgent.contains("iOS")) {
            return "iOS";
        }

        // 데스크톱 OS
        if (userAgent.contains("Windows NT") || userAgent.contains("Windows")) {
            return "Windows";
        }
        if (userAgent.contains("Mac OS X") || userAgent.contains("Macintosh")) {
            return "Mac";
        }
        if (userAgent.contains("CrOS")) {
            return "ChromeOS";
        }
        if (userAgent.contains("Linux")) {
            return "Linux";
        }

        // 모바일 패턴 감지 (OS 특정 불가 시)
        if (userAgent.contains("Mobile") || userAgent.contains("Tablet")) {
            return "Mobile";
        }

        // 기본값: Desktop (unknown 대신)
        return "Desktop";
    }

    /**
     * AI Native v11.0: UserAgent에서 브라우저/버전 시그니처 추출
     *
     * PRE-COMPUTED COMPARISON에서 UA 비교에 사용
     * OS는 별도 필드(userAgentOS)로 저장하므로 브라우저/버전만 추출
     *
     * @param userAgent User-Agent 문자열
     * @return 브라우저/메이저버전 (예: "Chrome/120")
     */
    protected String extractBrowserSignature(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }

        // Edge (Chromium 기반이므로 Chrome보다 먼저 검사)
        if (userAgent.contains("Edg/")) {
            return extractBrowserVersion(userAgent, "Edg/", "Edge");
        }

        // Chrome
        if (userAgent.contains("Chrome/") && !userAgent.contains("Edg/")) {
            return extractBrowserVersion(userAgent, "Chrome/", "Chrome");
        }

        // Firefox
        if (userAgent.contains("Firefox/")) {
            return extractBrowserVersion(userAgent, "Firefox/", "Firefox");
        }

        // Safari (Chrome, Edge가 아닌 경우만)
        if (userAgent.contains("Safari/") && userAgent.contains("Version/")) {
            return extractBrowserVersion(userAgent, "Version/", "Safari");
        }

        // Opera
        if (userAgent.contains("OPR/")) {
            return extractBrowserVersion(userAgent, "OPR/", "Opera");
        }

        return null;
    }

    /**
     * AI Native v11.0: User-Agent에서 브라우저 버전 추출 (메이저 버전만)
     */
    private String extractBrowserVersion(String userAgent, String prefix, String browserName) {
        int idx = userAgent.indexOf(prefix);
        if (idx == -1) return null;

        int start = idx + prefix.length();
        if (start >= userAgent.length()) return null;

        int end = start;
        while (end < userAgent.length()) {
            char c = userAgent.charAt(end);
            if (c == '.' || c == ' ' || !Character.isDigit(c)) {
                break;
            }
            end++;
        }

        if (end == start) return null;

        String version = userAgent.substring(start, end);
        return browserName + "/" + version;
    }
}