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
        
        if (chatClientBuilder != null && vectorStore != null) {
            createBehaviorAdvisor();
        }
        
        registry.registerRetriever(BehavioralAnalysisContext.class, this);
            }

    private void createBehaviorAdvisor() {
        
        QueryTransformer behaviorQueryTransformer = new BehaviorQueryTransformer(chatClientBuilder);

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        
        var filter = filterBuilder.and(
            filterBuilder.in("documentType",
                VectorDocumentType.BEHAVIOR.getValue(),
                VectorDocumentType.AUDIT.getValue(),
                VectorDocumentType.ACTIVITY.getValue(),
                VectorDocumentType.ANOMALY.getValue()),
            filterBuilder.gte("relevanceScore", 0.6)
        ).build();

        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(behaviorSimilarityThreshold)
            .topK(behaviorTopK)
            .filterExpression(filter)
            .build();

        behaviorAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(behaviorQueryTransformer)
            .build();
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof BehavioralAnalysisContext) {
            BehavioralAnalysisContext context = (BehavioralAnalysisContext) request.getContext();

            List<Document> vectorServiceDocs = List.of();
            try {
                String remoteIp = context.getRemoteIp();
                String requestPath = context.getMetadata() != null ?
                        (String) context.getMetadata().get("requestUri") : null;
                vectorServiceDocs = vectorService.findSimilarBehaviors(
                    context.getUserId(),
                    remoteIp,
                    requestPath,
                    10
                );
            } catch (Exception e) {
                log.error("Vector service search failed", e);
            }

            String contextInfo = retrieveBehavioralContext(
                (AIRequest<BehavioralAnalysisContext>) request,
                vectorServiceDocs
            );

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("retrieverType", "BehavioralAnalysisContextRetriever");
            metadata.put("timestamp", System.currentTimeMillis());
            metadata.put("ragEnabled", behaviorAdvisor != null);
            metadata.put("vectorServiceUsed", true);
            metadata.put("vectorServiceDocsCount", vectorServiceDocs.size());

            return new ContextRetrievalResult(
                    contextInfo,
                    vectorServiceDocs,
                    metadata
            );
        }
        return super.retrieveContext(request);
    }

    public String retrieveBehavioralContext(AIRequest<BehavioralAnalysisContext> request, List<Document> ragDocuments) {

        try {
            BehavioralAnalysisContext context = request.getContext();

            Document currentBehaviorVector = vectorizeBehavior(context);

            List<Document> historicalPatterns = searchSimilarBehaviors(context.getUserId(), currentBehaviorVector);

            BehaviorClusters clusters = analyzeBehaviorClusters(historicalPatterns);

            BehaviorBaseline baseline = calculateBaseline(clusters, context);

            List<String> anomalyFactors = detectAnomalyFactors(currentBehaviorVector, baseline, clusters);

            PeerGroupAnalysis peerAnalysis = analyzePeerGroup(context);

            List<RiskEvent> recentRiskEvents = analyzeRecentRiskEvents(context.getUserId());

            return buildComprehensiveContext(
                    context,
                    baseline,
                    anomalyFactors,
                    clusters,
                    peerAnalysis,
                    recentRiskEvents,
                    ragDocuments
            );

        } catch (Exception e) {
            log.error("Behavioral pattern analysis failed", e);
            return getDefaultContext();
        }
    }

    private Document vectorizeBehavior(BehavioralAnalysisContext context) {
        Map<String, Object> metadata = new HashMap<>();

        LocalDateTime now = LocalDateTime.now();

        metadata.put("userId", context.getUserId());
        metadata.put("timestamp", now.toString());
        metadata.put("hourOfDay", now.getHour());
        metadata.put("dayOfWeek", now.getDayOfWeek().getValue());
        metadata.put("isWeekend", isWeekend(now));
        metadata.put("isBusinessHours", isBusinessHours(now));

        metadata.put("activity", context.getCurrentActivity());
        metadata.put("activityType", extractActivityType(context.getCurrentActivity()));
        metadata.put("resourceAccessed", extractResource(context.getCurrentActivity()));

        metadata.put("remoteIp", context.getRemoteIp());
        metadata.put("ipType", categorizeIp(context.getRemoteIp()));
        metadata.put("isInternalNetwork", isInternalIp(context.getRemoteIp()));

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

    private List<Document> searchSimilarBehaviors(String userId, Document currentBehavior) {
        try {
            
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(currentBehavior.getText())
                    .topK(SIMILARITY_SEARCH_LIMIT)
                    .filterExpression(String.format("userId == '%s'", userId))
                    .similarityThreshold(0.5)
                    .build();

            List<Document> results = vectorStore.similaritySearch(searchRequest);

            return results;

        } catch (Exception e) {
            log.error("Vector search failed, returning empty list", e);
            return new ArrayList<>();
        }
    }

    private BehaviorClusters analyzeBehaviorClusters(List<Document> behaviors) {
        BehaviorClusters clusters = new BehaviorClusters();

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

        Map<String, List<Document>> activityClusters = behaviors.stream()
                .collect(Collectors.groupingBy(doc ->
                        (String) doc.getMetadata().getOrDefault("activityType", "UNKNOWN")
                ));

        clusters.setActivityClusters(activityClusters);

        Map<String, List<Document>> ipClusters = behaviors.stream()
                .collect(Collectors.groupingBy(doc ->
                        (String) doc.getMetadata().getOrDefault("ipType", "UNKNOWN")
                ));

        clusters.setIpClusters(ipClusters);

        return clusters;
    }

    private BehaviorBaseline calculateBaseline(BehaviorClusters clusters, BehavioralAnalysisContext context) {
        BehaviorBaseline baseline = new BehaviorBaseline();

        String currentTimeCluster = getCurrentTimeCluster();
        List<Document> timeClusterBehaviors = clusters.getTimeBasedClusters().get(currentTimeCluster);

        if (timeClusterBehaviors != null && !timeClusterBehaviors.isEmpty()) {
            
            Map<String, Long> activityFrequency = timeClusterBehaviors.stream()
                    .map(doc -> (String) doc.getMetadata().get("activityType"))
                    .collect(Collectors.groupingBy(act -> act, Collectors.counting()));

            baseline.setCommonActivities(activityFrequency);

            Map<String, Long> ipFrequency = timeClusterBehaviors.stream()
                    .map(doc -> (String) doc.getMetadata().get("ipType"))
                    .collect(Collectors.groupingBy(ip -> ip, Collectors.counting()));

            baseline.setCommonIpTypes(ipFrequency);

            baseline.setNormalBehaviorCount(timeClusterBehaviors.size());
            baseline.setTimeCluster(currentTimeCluster);
        }

        return baseline;
    }

    private List<String> detectAnomalyFactors(Document currentBehavior, BehaviorBaseline baseline, BehaviorClusters clusters) {
        List<String> anomalyFactors = new ArrayList<>();

        String currentTimeCluster = getCurrentTimeCluster();
        List<Document> expectedBehaviors = clusters.getTimeBasedClusters().get(currentTimeCluster);

        if (expectedBehaviors == null || expectedBehaviors.isEmpty()) {
            anomalyFactors.add("No activity record in this time period");
        }

        String currentActivity = (String) currentBehavior.getMetadata().get("activityType");
        if (!baseline.getCommonActivities().containsKey(currentActivity)) {
            anomalyFactors.add("Unusual activity type");
        }

        String currentIpType = (String) currentBehavior.getMetadata().get("ipType");
        if (!baseline.getCommonIpTypes().containsKey(currentIpType)) {
            anomalyFactors.add("Unusual network location");
        }

        boolean isWeekend = (boolean) currentBehavior.getMetadata().get("isWeekend");
        if (isWeekend && currentTimeCluster.startsWith("WEEKDAY")) {
            anomalyFactors.add("Weekend activity with weekday pattern");
        }

        return anomalyFactors;
    }

    private PeerGroupAnalysis analyzePeerGroup(BehavioralAnalysisContext context) {
        PeerGroupAnalysis analysis = new PeerGroupAnalysis();

        try {
            
            Users currentUser = userRepository.findByUsernameWithGroupsRolesAndPermissions(context.getUserId())
                    .orElse(null);

            if (currentUser != null) {
                
                Set<String> peerUserIds = new HashSet<>();
                currentUser.getUserGroups().forEach(userGroup -> {
                    userGroup.getGroup().getUserGroups().stream()
                            .filter(ug -> !ug.getUser().getUsername().equals(context.getUserId()))
                            .forEach(ug -> peerUserIds.add(ug.getUser().getUsername()));
                });

                LocalDateTime now = LocalDateTime.now();
                LocalDateTime startTime = now.minusHours(1);

                Map<String, Long> peerActivityCount = new HashMap<>();
                for (String peerId : peerUserIds) {
                    long activityCount = auditLogRepository.countByPrincipalNameAndTimeRange(
                            peerId, startTime, now);
                    peerActivityCount.put(peerId, activityCount);
                }

                double avgPeerActivity = peerActivityCount.values().stream()
                        .mapToLong(Long::longValue)
                        .average()
                        .orElse(0.0);

                analysis.setPeerGroupSize(peerUserIds.size());
                analysis.setAveragePeerActivity(avgPeerActivity);
                analysis.setCurrentUserDeviation(calculateDeviation(1.0, avgPeerActivity)); 
            }

        } catch (Exception e) {
            log.error("Peer group analysis failed", e);
        }

        return analysis;
    }

    private List<RiskEvent> analyzeRecentRiskEvents(String userId) {
        List<RiskEvent> riskEvents = new ArrayList<>();

        try {

            List<AuditLog> recentFailures = auditLogRepository.findRecentFailedAttemptsByUser(
                    userId, LocalDateTime.now().minusDays(7));

            recentFailures.forEach(auditLog -> {
                RiskEvent event = new RiskEvent();
                event.setTimestamp(auditLog.getTimestamp());
                event.setEventType("FAILED_ATTEMPT");
                event.setDescription(String.format("Failed attempt: %s", auditLog.getAction()));
                riskEvents.add(event);
            });

            List<AuditLog> afterHoursAccess = auditLogRepository.findAfterHoursAccessByUser(
                    userId, LocalDateTime.now().minusDays(7));

            afterHoursAccess.forEach(auditLog -> {
                RiskEvent event = new RiskEvent();
                event.setTimestamp(auditLog.getTimestamp());
                event.setEventType("AFTER_HOURS_ACCESS");
                event.setDescription(String.format("After hours access: %s", auditLog.getAction()));
                riskEvents.add(event);
            });

        } catch (Exception e) {
            log.error("Risk event analysis failed", e);
        }

        return riskEvents;
    }

    private String buildComprehensiveContext(
            BehavioralAnalysisContext context,
            BehaviorBaseline baseline,
            List<String> anomalyFactors,
            BehaviorClusters clusters,
            PeerGroupAnalysis peerAnalysis,
            List<RiskEvent> riskEvents,
            List<Document> ragDocuments) {

        StringBuilder contextBuilder = new StringBuilder();

        contextBuilder.append("## User Behavior Analysis Context\n\n");
        contextBuilder.append("### 1. Analysis Target Information\n");
        contextBuilder.append(String.format("- User ID: %s\n", context.getUserId()));
        contextBuilder.append(String.format("- Current Activity: %s\n", context.getCurrentActivity()));
        contextBuilder.append(String.format("- Access IP: %s (%s)\n", context.getRemoteIp(), categorizeIp(context.getRemoteIp())));
        contextBuilder.append(String.format("- Analysis Time: %s\n\n", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)));

        contextBuilder.append("### 2. Normal Behavior Patterns (Last 30 Days)\n");
        contextBuilder.append(String.format("- Activity count in current time period (%s): %d\n",
                baseline.getTimeCluster(), baseline.getNormalBehaviorCount()));

        if (!baseline.getCommonActivities().isEmpty()) {
            contextBuilder.append("- Major activity types:\n");
            baseline.getCommonActivities().entrySet().stream()
                    .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                    .limit(5)
                    .forEach(entry -> contextBuilder.append(
                            String.format("  * %s: %d times\n", entry.getKey(), entry.getValue())));
        }

        if (!baseline.getCommonIpTypes().isEmpty()) {
            contextBuilder.append("- Major access locations:\n");
            baseline.getCommonIpTypes().forEach((ipType, count) ->
                    contextBuilder.append(String.format("  * %s: %d times\n", ipType, count)));
        }
        contextBuilder.append("\n");

        contextBuilder.append("### 3. Anomaly Detection\n");
        if (!anomalyFactors.isEmpty()) {
            contextBuilder.append("- Detected anomaly factors:\n");
            anomalyFactors.forEach(factor ->
                    contextBuilder.append(String.format("  * %s\n", factor)));
        } else {
            contextBuilder.append("- No anomaly factors detected\n");
        }
        contextBuilder.append("\n");

        contextBuilder.append("### 4. Time-based Behavior Distribution\n");
        clusters.getTimeBasedClusters().forEach((timeCluster, behaviors) -> {
            contextBuilder.append(String.format("- %s: %d times\n",
                    translateTimeCluster(timeCluster), behaviors.size()));
        });
        contextBuilder.append("\n");

        contextBuilder.append("### 5. Peer Group Comparison\n");
        contextBuilder.append(String.format("- Peer group size: %d members\n", peerAnalysis.getPeerGroupSize()));
        contextBuilder.append(String.format("- Average peer activity: %.1f\n", peerAnalysis.getAveragePeerActivity()));
        contextBuilder.append(String.format("- Current user deviation: %.1f%%\n\n", peerAnalysis.getCurrentUserDeviation()));

        if (!riskEvents.isEmpty()) {
            contextBuilder.append("### 6. Recent Risk Events (7 Days)\n");
            riskEvents.stream()
                    .sorted(Comparator.comparing(RiskEvent::getTimestamp).reversed())
                    .limit(5)
                    .forEach(event -> contextBuilder.append(
                            String.format("- %s: %s (%s)\n",
                                    event.getTimestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                                    event.getDescription(),
                                    event.getEventType())));
            contextBuilder.append("\n");
        }

        if (ragDocuments != null && !ragDocuments.isEmpty()) {
            contextBuilder.append("### 7. Related Behavior Patterns (RAG)\n");
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

        contextBuilder.append("### 8. AI Analysis Guide\n");
        contextBuilder.append("Based on the above information, please determine the appropriate action:\n");
        contextBuilder.append("1. ALLOW - Normal behavior within expected patterns\n");
        contextBuilder.append("2. CHALLENGE - Requires additional verification\n");
        contextBuilder.append("3. BLOCK - High risk behavior requiring immediate blocking\n");
        contextBuilder.append("4. ESCALATE - Requires human security analyst review\n");

        return contextBuilder.toString();
    }

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
            case "WEEKEND": return "Weekend";
            case "WEEKDAY_MORNING": return "Weekday Morning (06:00-09:00)";
            case "WEEKDAY_BUSINESS": return "Weekday Business Hours (09:00-18:00)";
            case "WEEKDAY_EVENING": return "Weekday Evening (18:00-22:00)";
            case "WEEKDAY_NIGHT": return "Weekday Night (22:00-06:00)";
            default: return cluster;
        }
    }

    private double calculateDeviation(double current, double average) {
        if (average == 0) return 0;
        return Math.abs(current - average) / average * 100;
    }

    private String getDefaultContext() {
        return """
        ## Default Behavior Analysis Context

        Insufficient data for behavior pattern analysis.
        Proceeding with default security policy.
        """;
    }

    private static class BehaviorClusters {
        private Map<String, List<Document>> timeBasedClusters = new HashMap<>();
        private Map<String, List<Document>> activityClusters = new HashMap<>();
        private Map<String, List<Document>> ipClusters = new HashMap<>();

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

        public String getTimeCluster() { return timeCluster; }
        public void setTimeCluster(String cluster) { this.timeCluster = cluster; }
        public Map<String, Long> getCommonActivities() { return commonActivities; }
        public void setCommonActivities(Map<String, Long> activities) { this.commonActivities = activities; }
        public Map<String, Long> getCommonIpTypes() { return commonIpTypes; }
        public void setCommonIpTypes(Map<String, Long> ipTypes) { this.commonIpTypes = ipTypes; }
        public int getNormalBehaviorCount() { return normalBehaviorCount; }
        public void setNormalBehaviorCount(int count) { this.normalBehaviorCount = count; }
    }

    private static class PeerGroupAnalysis {
        private int peerGroupSize;
        private double averagePeerActivity;
        private double currentUserDeviation;

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

        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
        public String getEventType() { return eventType; }
        public void setEventType(String type) { this.eventType = type; }
        public String getDescription() { return description; }
        public void setDescription(String desc) { this.description = desc; }
    }

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