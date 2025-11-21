package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.DayOfWeek;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 사용자 행동 패턴 학습 컨텍스트 검색기 - Spring AI RAG + Vector + LLM 기반
 *
 * Spring AI RAG를 통한 행동 패턴 분석 및 이상 탐지
 * ML 없이 Vector Similarity와 LLM 추론으로 행동 패턴 학습
 * 시간대별, 위치별, 행동별 클러스터 자동 형성
 * 실시간 이상 탐지와 지속적 학습 동시 수행
 */
@Slf4j
public class BehavioralAnalysisContextRetriever extends ContextRetriever {

    private final ContextRetrieverRegistry registry;
    private final AuditLogRepository auditLogRepository;
    private final UserRepository userRepository;
    private final BehaviorVectorService vectorService;
    
    @Autowired(required = false)
    private ChatClient.Builder chatClientBuilder;
    
    @Value("${spring.ai.rag.behavior.similarity-threshold:0.7}")
    private double behaviorSimilarityThreshold;
    
    @Value("${spring.ai.rag.behavior.top-k:25}")
    private int behaviorTopK;
    
    private RetrievalAugmentationAdvisor behaviorAdvisor;

    // 행동 패턴 분석 상수
    private static final int SIMILARITY_SEARCH_LIMIT = 100;
    private static final double ANOMALY_THRESHOLD = 0.7;
    private static final int BASELINE_DAYS = 30;
    private static final int PEER_GROUP_SIZE = 10;

    public BehavioralAnalysisContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry registry,
            AuditLogRepository auditLogRepository,
            UserRepository userRepository,
            BehaviorVectorService vectorService) {
        super(vectorStore);
        this.registry = registry;
        this.auditLogRepository = auditLogRepository;
        this.userRepository = userRepository;
        this.vectorService = vectorService;
    }

    @PostConstruct
    public void registerSelf() {
        // RAG Advisor 생성 (사용 가능한 경우)
        if (chatClientBuilder != null && vectorStore != null) {
            createBehaviorAdvisor();
        }
        
        registry.registerRetriever(BehavioralAnalysisContext.class, this);
        log.info("BehavioralAnalysisContextRetriever 자동 등록 완료 (Spring AI RAG 지원)");
    }
    
    /**
     * 행동 분석 전용 RAG Advisor 생성
     */
    private void createBehaviorAdvisor() {
        // 행동 분석 쿼리 변환기
        QueryTransformer behaviorQueryTransformer = new BehaviorQueryTransformer(chatClientBuilder);
        
        // 행동 분석 필터 구성
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.in("documentType",
                VectorDocumentType.BEHAVIOR.getValue(),
                "audit",  // TODO: VectorDocumentType에 추가 필요
                "activity",  // TODO: VectorDocumentType에 추가 필요
                "anomaly"),  // TODO: VectorDocumentType에 추가 필요
            filterBuilder.gte("relevanceScore", 0.6)
        ).build();
        
        // VectorStoreDocumentRetriever 구성
        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(behaviorSimilarityThreshold)
            .topK(behaviorTopK)
            .filterExpression(filter)
            .build();
        
        // Behavior RAG Advisor 생성
        behaviorAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(behaviorQueryTransformer)
            .build();
        
        // 부모 클래스에 Advisor 등록
        registerDomainAdvisor(BehavioralAnalysisContext.class, behaviorAdvisor);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof BehavioralAnalysisContext) {
            BehavioralAnalysisContext context = (BehavioralAnalysisContext) request.getContext();
            
            // VectorService에 행동 컨텍스트 저장
            try {
                vectorService.storeBehaviorContext(context);
            } catch (Exception e) {
                log.error("벡터 저장소 컨텍스트 저장 실패", e);
            }
            
            // RAG 기반 검색 시도
            ContextRetrievalResult ragResult = null;
            if (behaviorAdvisor != null) {
                ragResult = super.retrieveContext(request);
            }
            
            // VectorService를 통한 유사 행동 패턴 검색
            List<Document> vectorServiceDocs = List.of();
            try {
                vectorServiceDocs = vectorService.findSimilarBehaviors(
                    context.getUserId(), 
                    context.getCurrentActivity(), 
                    10
                );
            } catch (Exception e) {
                log.error("벡터 서비스 검색 실패", e);
            }
            
            // RAG 결과와 VectorService 결과 병합
            List<Document> allDocuments = new ArrayList<>();
            if (ragResult != null && ragResult.getDocuments() != null) {
                allDocuments.addAll(ragResult.getDocuments());
            }
            allDocuments.addAll(vectorServiceDocs);
            
            String contextInfo = retrieveBehavioralContext(
                (AIRequest<BehavioralAnalysisContext>) request,
                allDocuments
            );
            
            Map<String, Object> metadata = new HashMap<>();
            if (ragResult != null) {
                metadata.putAll(ragResult.getMetadata());
            }
            metadata.put("retrieverType", "BehavioralAnalysisContextRetriever");
            metadata.put("timestamp", System.currentTimeMillis());
            metadata.put("ragEnabled", behaviorAdvisor != null);
            metadata.put("vectorServiceUsed", true);
            metadata.put("vectorServiceDocsCount", vectorServiceDocs.size());
            
            return new ContextRetrievalResult(
                    contextInfo,
                    allDocuments,
                    metadata
            );
        }
        return super.retrieveContext(request);
    }

    /**
     * 행동 패턴 학습 기반 컨텍스트 검색
     */
    public String retrieveBehavioralContext(AIRequest<BehavioralAnalysisContext> request, List<Document> ragDocuments) {
        log.info("사용자 행동 패턴 분석 시작: {}", request.getContext().getUserId());

        try {
            BehavioralAnalysisContext context = request.getContext();

            // 1. 현재 행동을 벡터화
            Document currentBehaviorVector = vectorizeBehavior(context);

            // 2. Vector DB에서 과거 유사 행동 패턴 검색
            List<Document> historicalPatterns = searchSimilarBehaviors(context.getUserId(), currentBehaviorVector);

            // 3. 시간대별/행동별 클러스터 분석
            BehaviorClusters clusters = analyzeBehaviorClusters(historicalPatterns);

            // 4. 정상 행동 기준선(Baseline) 계산
            BehaviorBaseline baseline = calculateBaseline(clusters, context);

            // 5. 현재 행동의 이상 점수 계산
            AnomalyScore anomalyScore = calculateAnomalyScore(currentBehaviorVector, baseline, clusters);

            // 6. Peer Group 비교 분석
            PeerGroupAnalysis peerAnalysis = analyzePeerGroup(context);

            // 7. 최근 위험 이벤트 분석
            List<RiskEvent> recentRiskEvents = analyzeRecentRiskEvents(context.getUserId());

            // 8. LLM을 위한 종합 컨텍스트 구성
            return buildComprehensiveContext(
                    context,
                    baseline,
                    anomalyScore,
                    clusters,
                    peerAnalysis,
                    recentRiskEvents,
                    ragDocuments
            );

        } catch (Exception e) {
            log.error("행동 패턴 분석 실패", e);
            return getDefaultContext();
        }
    }

    /**
     * 현재 행동을 벡터로 변환
     */
    private Document vectorizeBehavior(BehavioralAnalysisContext context) {
        Map<String, Object> metadata = new HashMap<>();

        LocalDateTime now = LocalDateTime.now();

        // 시간 특성
        metadata.put("userId", context.getUserId());
        metadata.put("timestamp", now.toString());
        metadata.put("hourOfDay", now.getHour());
        metadata.put("dayOfWeek", now.getDayOfWeek().getValue());
        metadata.put("isWeekend", isWeekend(now));
        metadata.put("isBusinessHours", isBusinessHours(now));

        // 행동 특성
        metadata.put("activity", context.getCurrentActivity());
        metadata.put("activityType", extractActivityType(context.getCurrentActivity()));
        metadata.put("resourceAccessed", extractResource(context.getCurrentActivity()));

        // 위치 특성
        metadata.put("remoteIp", context.getRemoteIp());
        metadata.put("ipType", categorizeIp(context.getRemoteIp()));
        metadata.put("isInternalNetwork", isInternalIp(context.getRemoteIp()));

        // 벡터 임베딩을 위한 텍스트 구성
        String vectorText = String.format(
                "User %s performed %s from %s at %s on %s (hour:%d, %s)",
                context.getUserId(),
                context.getCurrentActivity(),
                context.getRemoteIp(),
                now.toLocalTime(),
                now.getDayOfWeek(),
                now.getHour(),
                isBusinessHours(now) ? "business-hours" : "after-hours"
        );

        return new Document(vectorText, metadata);
    }

    /**
     * Vector DB에서 유사 행동 패턴 검색
     */
    private List<Document> searchSimilarBehaviors(String userId, Document currentBehavior) {
        try {
            // 사용자의 과거 행동 패턴 검색
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(currentBehavior.getText())
                    .topK(SIMILARITY_SEARCH_LIMIT)
                    .filterExpression(String.format("userId == '%s'", userId))
                    .similarityThreshold(0.5)
                    .build();

            List<Document> results = vectorStore.similaritySearch(searchRequest);

            log.info("사용자 {}의 과거 유사 행동 {}개 검색됨", userId, results.size());

            return results;

        } catch (Exception e) {
            log.warn("Vector 검색 실패, 빈 리스트 반환", e);
            return new ArrayList<>();
        }
    }

    /**
     * 행동 클러스터 분석
     */
    private BehaviorClusters analyzeBehaviorClusters(List<Document> behaviors) {
        BehaviorClusters clusters = new BehaviorClusters();

        // 시간대별 클러스터링
        Map<String, List<Document>> timeBasedClusters = behaviors.stream()
                .collect(Collectors.groupingBy(doc -> {
                    int hour = (int) doc.getMetadata().getOrDefault("hourOfDay", 0);
                    boolean isWeekend = (boolean) doc.getMetadata().getOrDefault("isWeekend", false);

                    if (isWeekend) return "WEEKEND";
                    else if (hour >= 6 && hour < 9) return "WEEKDAY_MORNING";
                    else if (hour >= 9 && hour < 18) return "WEEKDAY_BUSINESS";
                    else if (hour >= 18 && hour < 22) return "WEEKDAY_EVENING";
                    else return "WEEKDAY_NIGHT";
                }));

        clusters.setTimeBasedClusters(timeBasedClusters);

        // 활동 유형별 클러스터링
        Map<String, List<Document>> activityClusters = behaviors.stream()
                .collect(Collectors.groupingBy(doc ->
                        (String) doc.getMetadata().getOrDefault("activityType", "UNKNOWN")
                ));

        clusters.setActivityClusters(activityClusters);

        // IP 유형별 클러스터링
        Map<String, List<Document>> ipClusters = behaviors.stream()
                .collect(Collectors.groupingBy(doc ->
                        (String) doc.getMetadata().getOrDefault("ipType", "UNKNOWN")
                ));

        clusters.setIpClusters(ipClusters);

        return clusters;
    }

    /**
     * 정상 행동 기준선 계산
     */
    private BehaviorBaseline calculateBaseline(BehaviorClusters clusters, BehavioralAnalysisContext context) {
        BehaviorBaseline baseline = new BehaviorBaseline();

        // 현재 시간대의 정상 패턴
        String currentTimeCluster = getCurrentTimeCluster();
        List<Document> timeClusterBehaviors = clusters.getTimeBasedClusters().get(currentTimeCluster);

        if (timeClusterBehaviors != null && !timeClusterBehaviors.isEmpty()) {
            // 가장 빈번한 활동 유형
            Map<String, Long> activityFrequency = timeClusterBehaviors.stream()
                    .map(doc -> (String) doc.getMetadata().get("activityType"))
                    .collect(Collectors.groupingBy(act -> act, Collectors.counting()));

            baseline.setCommonActivities(activityFrequency);

            // 가장 빈번한 IP 유형
            Map<String, Long> ipFrequency = timeClusterBehaviors.stream()
                    .map(doc -> (String) doc.getMetadata().get("ipType"))
                    .collect(Collectors.groupingBy(ip -> ip, Collectors.counting()));

            baseline.setCommonIpTypes(ipFrequency);

            // 정상 범위 통계
            baseline.setNormalBehaviorCount(timeClusterBehaviors.size());
            baseline.setTimeCluster(currentTimeCluster);
        }

        return baseline;
    }

    /**
     * 이상 점수 계산
     */
    private AnomalyScore calculateAnomalyScore(Document currentBehavior, BehaviorBaseline baseline, BehaviorClusters clusters) {
        AnomalyScore score = new AnomalyScore();
        double totalScore = 0.0;
        List<String> anomalyFactors = new ArrayList<>();

        // 1. 시간대 이상 점수
        String currentTimeCluster = getCurrentTimeCluster();
        List<Document> expectedBehaviors = clusters.getTimeBasedClusters().get(currentTimeCluster);

        if (expectedBehaviors == null || expectedBehaviors.isEmpty()) {
            totalScore += 30.0;
            anomalyFactors.add("이 시간대에 활동 기록이 없음");
        }

        // 2. 활동 유형 이상 점수
        String currentActivity = (String) currentBehavior.getMetadata().get("activityType");
        if (!baseline.getCommonActivities().containsKey(currentActivity)) {
            totalScore += 25.0;
            anomalyFactors.add("평소와 다른 활동 유형");
        }

        // 3. IP 유형 이상 점수
        String currentIpType = (String) currentBehavior.getMetadata().get("ipType");
        if (!baseline.getCommonIpTypes().containsKey(currentIpType)) {
            totalScore += 25.0;
            anomalyFactors.add("평소와 다른 네트워크 위치");
        }

        // 4. 주말/평일 패턴 위반
        boolean isWeekend = (boolean) currentBehavior.getMetadata().get("isWeekend");
        if (isWeekend && currentTimeCluster.startsWith("WEEKDAY")) {
            totalScore += 20.0;
            anomalyFactors.add("주말에 평일 패턴 활동");
        }

        score.setScore(Math.min(totalScore, 100.0));
        score.setAnomalyFactors(anomalyFactors);
        score.setRiskLevel(determineRiskLevel(totalScore));

        return score;
    }

    /**
     * 👥 Peer Group 분석
     */
    private PeerGroupAnalysis analyzePeerGroup(BehavioralAnalysisContext context) {
        PeerGroupAnalysis analysis = new PeerGroupAnalysis();

        try {
            // 현재 사용자 정보 조회
            Users currentUser = userRepository.findByUsernameWithGroupsRolesAndPermissions(context.getUserId())
                    .orElse(null);

            if (currentUser != null) {
                // 같은 그룹의 다른 사용자들 조회
                Set<String> peerUserIds = new HashSet<>();
                currentUser.getUserGroups().forEach(userGroup -> {
                    userGroup.getGroup().getUserGroups().stream()
                            .filter(ug -> !ug.getUser().getUsername().equals(context.getUserId()))
                            .forEach(ug -> peerUserIds.add(ug.getUser().getUsername()));
                });

                // Peer들의 현재 시간대 활동 패턴
                LocalDateTime now = LocalDateTime.now();
                LocalDateTime startTime = now.minusHours(1);

                Map<String, Long> peerActivityCount = new HashMap<>();
                for (String peerId : peerUserIds) {
                    long activityCount = auditLogRepository.countByPrincipalNameAndTimeRange(
                            peerId, startTime, now);
                    peerActivityCount.put(peerId, activityCount);
                }

                // 평균 활동량 계산
                double avgPeerActivity = peerActivityCount.values().stream()
                        .mapToLong(Long::longValue)
                        .average()
                        .orElse(0.0);

                analysis.setPeerGroupSize(peerUserIds.size());
                analysis.setAveragePeerActivity(avgPeerActivity);
                analysis.setCurrentUserDeviation(calculateDeviation(1.0, avgPeerActivity)); // 현재 활동 = 1
            }

        } catch (Exception e) {
            log.warn("Peer Group 분석 실패", e);
        }

        return analysis;
    }

    /**
     * 최근 위험 이벤트 분석
     */
    private List<RiskEvent> analyzeRecentRiskEvents(String userId) {
        List<RiskEvent> riskEvents = new ArrayList<>();

        try {
            // 최근 실패한 시도들
            List<AuditLog> recentFailures = auditLogRepository.findRecentFailedAttemptsByUser(
                    userId, LocalDateTime.now().minusDays(7));

            recentFailures.forEach(log -> {
                RiskEvent event = new RiskEvent();
                event.setTimestamp(log.getTimestamp());
                event.setEventType("FAILED_ATTEMPT");
                event.setDescription(String.format("실패한 시도: %s", log.getAction()));
                event.setRiskScore(calculateFailureRisk(log));
                riskEvents.add(event);
            });

            // 비정상 시간대 접근
            List<AuditLog> afterHoursAccess = auditLogRepository.findAfterHoursAccessByUser(
                    userId, LocalDateTime.now().minusDays(7));

            afterHoursAccess.forEach(log -> {
                RiskEvent event = new RiskEvent();
                event.setTimestamp(log.getTimestamp());
                event.setEventType("AFTER_HOURS_ACCESS");
                event.setDescription(String.format("업무시간 외 접근: %s", log.getAction()));
                event.setRiskScore(20.0);
                riskEvents.add(event);
            });

        } catch (Exception e) {
            log.warn("위험 이벤트 분석 실패", e);
        }

        return riskEvents;
    }

    /**
     * LLM을 위한 종합 컨텍스트 구성
     */
    private String buildComprehensiveContext(
            BehavioralAnalysisContext context,
            BehaviorBaseline baseline,
            AnomalyScore anomalyScore,
            BehaviorClusters clusters,
            PeerGroupAnalysis peerAnalysis,
            List<RiskEvent> riskEvents,
            List<Document> ragDocuments) {

        StringBuilder contextBuilder = new StringBuilder();

        // 1. 사용자 기본 정보
        contextBuilder.append("## 사용자 행동 분석 컨텍스트\n\n");
        contextBuilder.append("### 1. 분석 대상 정보\n");
        contextBuilder.append(String.format("- 사용자 ID: %s\n", context.getUserId()));
        contextBuilder.append(String.format("- 현재 활동: %s\n", context.getCurrentActivity()));
        contextBuilder.append(String.format("- 접속 IP: %s (%s)\n", context.getRemoteIp(), categorizeIp(context.getRemoteIp())));
        contextBuilder.append(String.format("- 분석 시각: %s\n\n", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)));

        // 2. 정상 행동 기준선
        contextBuilder.append("### 2. 정상 행동 패턴 (최근 30일 기준)\n");
        contextBuilder.append(String.format("- 현재 시간대(%s) 활동 횟수: %d회\n",
                baseline.getTimeCluster(), baseline.getNormalBehaviorCount()));

        if (!baseline.getCommonActivities().isEmpty()) {
            contextBuilder.append("- 주요 활동 유형:\n");
            baseline.getCommonActivities().entrySet().stream()
                    .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                    .limit(5)
                    .forEach(entry -> contextBuilder.append(
                            String.format("  * %s: %d회\n", entry.getKey(), entry.getValue())));
        }

        if (!baseline.getCommonIpTypes().isEmpty()) {
            contextBuilder.append("- 주요 접속 위치:\n");
            baseline.getCommonIpTypes().forEach((ipType, count) ->
                    contextBuilder.append(String.format("  * %s: %d회\n", ipType, count)));
        }
        contextBuilder.append("\n");

        // 3. 이상 점수 분석
        contextBuilder.append("### 3. 이상 행동 분석\n");
        contextBuilder.append(String.format("- 종합 이상 점수: %.1f/100\n", anomalyScore.getScore()));
        contextBuilder.append(String.format("- 위험 수준: %s\n", anomalyScore.getRiskLevel()));

        if (!anomalyScore.getAnomalyFactors().isEmpty()) {
            contextBuilder.append("- 이상 요인:\n");
            anomalyScore.getAnomalyFactors().forEach(factor ->
                    contextBuilder.append(String.format("  * %s\n", factor)));
        }
        contextBuilder.append("\n");

        // 4. 시간대별 행동 패턴
        contextBuilder.append("### 4. 시간대별 행동 분포\n");
        clusters.getTimeBasedClusters().forEach((timeCluster, behaviors) -> {
            contextBuilder.append(String.format("- %s: %d회\n",
                    translateTimeCluster(timeCluster), behaviors.size()));
        });
        contextBuilder.append("\n");

        // 5. Peer Group 비교
        contextBuilder.append("### 5. 동료 그룹 비교\n");
        contextBuilder.append(String.format("- 동료 그룹 크기: %d명\n", peerAnalysis.getPeerGroupSize()));
        contextBuilder.append(String.format("- 동료 평균 활동량: %.1f\n", peerAnalysis.getAveragePeerActivity()));
        contextBuilder.append(String.format("- 현재 사용자 편차: %.1f%%\n\n", peerAnalysis.getCurrentUserDeviation()));

        // 6. 최근 위험 이벤트
        if (!riskEvents.isEmpty()) {
            contextBuilder.append("### 6. 최근 위험 이벤트 (7일)\n");
            riskEvents.stream()
                    .sorted(Comparator.comparing(RiskEvent::getTimestamp).reversed())
                    .limit(5)
                    .forEach(event -> contextBuilder.append(
                            String.format("- %s: %s (위험도: %.1f)\n",
                                    event.getTimestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                                    event.getDescription(),
                                    event.getRiskScore())));
            contextBuilder.append("\n");
        }

        // 7. RAG 검색 결과 (있는 경우)
        if (ragDocuments != null && !ragDocuments.isEmpty()) {
            contextBuilder.append("### 7. 관련 행동 패턴 참조 (RAG)\n");
            for (int i = 0; i < Math.min(5, ragDocuments.size()); i++) {
                Document doc = ragDocuments.get(i);
                contextBuilder.append("- ").append(doc.getText().substring(0, Math.min(150, doc.getText().length())));
                if (doc.getText().length() > 150) {
                    contextBuilder.append("...");
                }
                contextBuilder.append("\n");
            }
            contextBuilder.append("\n");
        }

        // 8. AI 분석 가이드
        contextBuilder.append("### 8. AI 분석 가이드\n");
        contextBuilder.append("위의 정보를 종합하여 다음을 평가해주세요:\n");
        contextBuilder.append("1. 현재 행동이 사용자의 정상 패턴에서 벗어난 정도\n");
        contextBuilder.append("2. 보안 위험도 (0-100 점수)\n");
        contextBuilder.append("3. 구체적인 이상 징후 설명\n");
        contextBuilder.append("4. 권장 대응 방안\n");

        return contextBuilder.toString();
    }

    // === Helper Methods ===

    private boolean isWeekend(LocalDateTime dateTime) {
        DayOfWeek dayOfWeek = dateTime.getDayOfWeek();
        return dayOfWeek == DayOfWeek.SATURDAY || dayOfWeek == DayOfWeek.SUNDAY;
    }

    private boolean isBusinessHours(LocalDateTime dateTime) {
        int hour = dateTime.getHour();
        return !isWeekend(dateTime) && hour >= 9 && hour < 18;
    }

    private String extractActivityType(String activity) {
        if (activity == null) return "UNKNOWN";

        String lower = activity.toLowerCase();
        if (lower.contains("login")) return "LOGIN";
        if (lower.contains("logout")) return "LOGOUT";
        if (lower.contains("create") || lower.contains("생성")) return "CREATE";
        if (lower.contains("update") || lower.contains("수정")) return "UPDATE";
        if (lower.contains("delete") || lower.contains("삭제")) return "DELETE";
        if (lower.contains("read") || lower.contains("조회")) return "READ";
        if (lower.contains("download") || lower.contains("다운로드")) return "DOWNLOAD";
        if (lower.contains("upload") || lower.contains("업로드")) return "UPLOAD";
        if (lower.contains("admin") || lower.contains("관리")) return "ADMIN_ACTION";

        return "OTHER";
    }

    private String extractResource(String activity) {
        if (activity == null) return "UNKNOWN";

        // URL 패턴 추출
        if (activity.contains("/api/")) {
            int start = activity.indexOf("/api/");
            int end = activity.indexOf(" ", start);
            if (end == -1) end = activity.length();
            return activity.substring(start, end);
        }

        return "N/A";
    }

    private String categorizeIp(String ip) {
        if (ip == null) return "UNKNOWN";

        if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.")) {
            return "INTERNAL_NETWORK";
        } else if (ip.startsWith("127.") || ip.equals("::1")) {
            return "LOCALHOST";
        } else {
            return "EXTERNAL_NETWORK";
        }
    }

    private boolean isInternalIp(String ip) {
        return "INTERNAL_NETWORK".equals(categorizeIp(ip));
    }

    private String getCurrentTimeCluster() {
        LocalDateTime now = LocalDateTime.now();
        int hour = now.getHour();
        boolean isWeekend = isWeekend(now);

        if (isWeekend) return "WEEKEND";
        else if (hour >= 6 && hour < 9) return "WEEKDAY_MORNING";
        else if (hour >= 9 && hour < 18) return "WEEKDAY_BUSINESS";
        else if (hour >= 18 && hour < 22) return "WEEKDAY_EVENING";
        else return "WEEKDAY_NIGHT";
    }

    private String translateTimeCluster(String cluster) {
        switch (cluster) {
            case "WEEKEND": return "주말";
            case "WEEKDAY_MORNING": return "평일 아침 (06:00-09:00)";
            case "WEEKDAY_BUSINESS": return "평일 업무시간 (09:00-18:00)";
            case "WEEKDAY_EVENING": return "평일 저녁 (18:00-22:00)";
            case "WEEKDAY_NIGHT": return "평일 심야 (22:00-06:00)";
            default: return cluster;
        }
    }

    private String determineRiskLevel(double score) {
        if (score >= 80) return "CRITICAL";
        else if (score >= 60) return "HIGH";
        else if (score >= 40) return "MEDIUM";
        else return "LOW";
    }

    private double calculateDeviation(double current, double average) {
        if (average == 0) return 0;
        return Math.abs(current - average) / average * 100;
    }

    private double calculateFailureRisk(AuditLog log) {
        // 실패 유형에 따른 위험도 계산
        if (log.getAction().contains("ADMIN")) return 40.0;
        if (log.getAction().contains("DELETE")) return 30.0;
        if (log.getAction().contains("EXPORT")) return 25.0;
        return 20.0;
    }

    private String getDefaultContext() {
        return """
        ## 기본 행동 분석 컨텍스트
        
        행동 패턴 분석을 위한 충분한 데이터가 없습니다.
        기본 보안 정책을 적용하여 분석을 진행합니다.
        """;
    }

    // === 내부 클래스들 ===

    private static class BehaviorClusters {
        private Map<String, List<Document>> timeBasedClusters = new HashMap<>();
        private Map<String, List<Document>> activityClusters = new HashMap<>();
        private Map<String, List<Document>> ipClusters = new HashMap<>();

        // Getters and Setters
        public Map<String, List<Document>> getTimeBasedClusters() { return timeBasedClusters; }
        public void setTimeBasedClusters(Map<String, List<Document>> clusters) { this.timeBasedClusters = clusters; }
        public Map<String, List<Document>> getActivityClusters() { return activityClusters; }
        public void setActivityClusters(Map<String, List<Document>> clusters) { this.activityClusters = clusters; }
        public Map<String, List<Document>> getIpClusters() { return ipClusters; }
        public void setIpClusters(Map<String, List<Document>> clusters) { this.ipClusters = clusters; }
    }

    private static class BehaviorBaseline {
        private String timeCluster;
        private Map<String, Long> commonActivities = new HashMap<>();
        private Map<String, Long> commonIpTypes = new HashMap<>();
        private int normalBehaviorCount;

        // Getters and Setters
        public String getTimeCluster() { return timeCluster; }
        public void setTimeCluster(String cluster) { this.timeCluster = cluster; }
        public Map<String, Long> getCommonActivities() { return commonActivities; }
        public void setCommonActivities(Map<String, Long> activities) { this.commonActivities = activities; }
        public Map<String, Long> getCommonIpTypes() { return commonIpTypes; }
        public void setCommonIpTypes(Map<String, Long> ipTypes) { this.commonIpTypes = ipTypes; }
        public int getNormalBehaviorCount() { return normalBehaviorCount; }
        public void setNormalBehaviorCount(int count) { this.normalBehaviorCount = count; }
    }

    private static class AnomalyScore {
        private double score;
        private String riskLevel;
        private List<String> anomalyFactors = new ArrayList<>();

        // Getters and Setters
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String level) { this.riskLevel = level; }
        public List<String> getAnomalyFactors() { return anomalyFactors; }
        public void setAnomalyFactors(List<String> factors) { this.anomalyFactors = factors; }
    }

    private static class PeerGroupAnalysis {
        private int peerGroupSize;
        private double averagePeerActivity;
        private double currentUserDeviation;

        // Getters and Setters
        public int getPeerGroupSize() { return peerGroupSize; }
        public void setPeerGroupSize(int size) { this.peerGroupSize = size; }
        public double getAveragePeerActivity() { return averagePeerActivity; }
        public void setAveragePeerActivity(double avg) { this.averagePeerActivity = avg; }
        public double getCurrentUserDeviation() { return currentUserDeviation; }
        public void setCurrentUserDeviation(double deviation) { this.currentUserDeviation = deviation; }
    }

    private static class RiskEvent {
        private LocalDateTime timestamp;
        private String eventType;
        private String description;
        private double riskScore;

        // Getters and Setters
        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
        public String getEventType() { return eventType; }
        public void setEventType(String type) { this.eventType = type; }
        public String getDescription() { return description; }
        public void setDescription(String desc) { this.description = desc; }
        public double getRiskScore() { return riskScore; }
        public void setRiskScore(double score) { this.riskScore = score; }
    }
    
    /**
     * 행동 분석 쿼리 변환기
     */
    private static class BehaviorQueryTransformer implements QueryTransformer {
        private final ChatClient chatClient;
        
        public BehaviorQueryTransformer(ChatClient.Builder chatClientBuilder) {
            this.chatClient = chatClientBuilder.build();
        }
        
        @Override
        public Query transform(Query originalQuery) {
            if (originalQuery == null || originalQuery.text() == null) {
                return originalQuery;
            }
            
            String prompt = String.format("""
                사용자 행동 분석을 위한 검색 쿼리를 최적화하세요:
                
                원본 쿼리: %s
                
                최적화 지침:
                1. 행동 패턴과 관련된 시간적 특성을 포함하세요
                2. 이상 행동 탐지 관련 용어를 추가하세요
                3. 사용자 활동 유형 및 접근 패턴을 구체화하세요
                4. 피어 그룹 비교를 위한 컨텍스트를 포함하세요
                5. 위험 지표와 관련된 키워드를 추가하세요
                
                최적화된 쿼리만 반환하세요.
                """, originalQuery.text());
            
            String transformedText = chatClient.prompt()
                .user(prompt)
                .call()
                .content();
                
            return new Query(transformedText);
        }
    }
}