package io.contexa.contexaiam.aiam.labs.studio;

import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import org.springframework.ai.vectorstore.VectorStore;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
public class StudioQueryVectorService extends AbstractVectorLabService {
    
    @Value("${spring.ai.studio.confidence-threshold:0.7}")
    private double confidenceThreshold;
    
    @Value("${spring.ai.studio.cache-similar-queries:true}")
    private boolean cacheSimilarQueries;
    
    @Value("${spring.ai.studio.learning-enabled:true}")
    private boolean learningEnabled;
    
    @Value("${spring.ai.studio.visualization-tracking:true}")
    private boolean visualizationTracking;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private static final Map<String, Pattern> QUERY_TYPE_PATTERNS = Map.of(
        "PERMISSION_QUERY", Pattern.compile("권한|permission|access|접근", Pattern.CASE_INSENSITIVE),
        "USER_QUERY", Pattern.compile("사용자|user|계정|account", Pattern.CASE_INSENSITIVE),
        "ROLE_QUERY", Pattern.compile("역할|role|권한.*그룹", Pattern.CASE_INSENSITIVE),
        "POLICY_QUERY", Pattern.compile("정책|policy|규칙|rule", Pattern.CASE_INSENSITIVE),
        "AUDIT_QUERY", Pattern.compile("감사|audit|로그|log|기록", Pattern.CASE_INSENSITIVE),
        "SECURITY_QUERY", Pattern.compile("보안|security|위험|risk|threat", Pattern.CASE_INSENSITIVE),
        "COMPLIANCE_QUERY", Pattern.compile("준수|compliance|규정|regulation", Pattern.CASE_INSENSITIVE),
        "ANALYTICS_QUERY", Pattern.compile("분석|analytics|통계|statistics|현황", Pattern.CASE_INSENSITIVE)
    );

    private static final Map<String, Pattern> INTENT_PATTERNS = Map.of(
        "INVESTIGATION", Pattern.compile("누가|who|어떤.*사용자|which.*user", Pattern.CASE_INSENSITIVE),
        "VERIFICATION", Pattern.compile("확인|verify|check|검증", Pattern.CASE_INSENSITIVE),
        "DISCOVERY", Pattern.compile("찾아|find|search|검색|discover", Pattern.CASE_INSENSITIVE),
        "ANALYSIS", Pattern.compile("분석|analyze|examine|조사", Pattern.CASE_INSENSITIVE),
        "REPORTING", Pattern.compile("보고|report|현황|status|요약", Pattern.CASE_INSENSITIVE),
        "TROUBLESHOOTING", Pattern.compile("문제|problem|오류|error|해결", Pattern.CASE_INSENSITIVE)
    );
    
    @Autowired
    public StudioQueryVectorService(VectorStore vectorStore,
                                   @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(vectorStore, vectorStoreMetrics);
    }
    
    @Override
    protected String getLabName() {
        return "StudioQuery";
    }
    
    @Override
    protected String getDocumentType() {
        return "studio_query";
    }
    
    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        Map<String, Object> metadata = new HashMap<>(document.getMetadata());
        
        try {
            
            String queryType = classifyQueryType(document.getText());
            metadata.put("queryType", queryType);

            String queryIntent = analyzeQueryIntent(document.getText());
            metadata.put("queryIntent", queryIntent);

            QueryComplexity complexity = evaluateQueryComplexity(document.getText(), metadata);
            metadata.put("complexityLevel", complexity.getLevel());
            metadata.put("complexityScore", complexity.getScore());
            metadata.put("complexityFactors", complexity.getFactors());

            Set<String> keywords = extractKeywords(document.getText());
            metadata.put("keywords", new ArrayList<>(keywords));
            metadata.put("keywordCount", keywords.size());

            Map<String, List<String>> entities = extractEntities(document.getText());
            metadata.put("entities", entities);
            metadata.put("hasUserEntities", !entities.getOrDefault("users", Collections.emptyList()).isEmpty());
            metadata.put("hasRoleEntities", !entities.getOrDefault("roles", Collections.emptyList()).isEmpty());
            metadata.put("hasResourceEntities", !entities.getOrDefault("resources", Collections.emptyList()).isEmpty());

            TimeContext timeContext = analyzeTimeContext(document.getText());
            metadata.put("timeContext", timeContext.getType() != null ? timeContext.getType() : "UNSPECIFIED");
            if (timeContext.getRange() != null) {
                metadata.put("timeRange", timeContext.getRange());
            }

            String securitySensitivity = evaluateSecuritySensitivity(document.getText(), metadata);
            metadata.put("securitySensitivity", securitySensitivity);

            String querySignature = generateQuerySignature(metadata);
            metadata.put("querySignature", querySignature);

            if (learningEnabled) {
                metadata.put("isLearningData", true);
                metadata.put("learningTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            }

            metadata.put("enrichmentVersion", "2.0");
            metadata.put("enrichedByService", "StudioQueryVectorService");
            
            return new Document(document.getText(), metadata);
            
        } catch (Exception e) {
            log.error("[StudioQueryVectorService] 메타데이터 강화 실패", e);
            metadata.put("enrichmentError", e.getMessage());
            return new Document(document.getText(), metadata);
        }
    }
    
    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("userId") && 
            !metadata.containsKey("queryType") && 
            !metadata.containsKey("naturalLanguageQuery")) {
            throw new IllegalArgumentException(
                "Studio Query 문서는 userId, queryType, naturalLanguageQuery 중 최소 하나는 포함해야 합니다");
        }

        String text = document.getText();
        if (text == null || text.trim().length() < 5) {
            throw new IllegalArgumentException("질의 내용이 너무 짧습니다 (최소 5자 필요)");
        }

        if (text.length() > 5000) {
            throw new IllegalArgumentException("질의 내용이 너무 깁니다 (최대 5000자)");
        }
    }
    
    @Override
    protected void postProcessDocument(Document document, OperationType operationType) {
        try {
            Map<String, Object> metadata = document.getMetadata();
            
            if (operationType == OperationType.STORE) {
                
                if (cacheSimilarQueries) {
                    Double confidence = (Double) metadata.get("confidenceScore");
                    if (confidence != null && confidence >= confidenceThreshold) {
                        metadata.put("isCacheable", true);
                        metadata.put("cacheExpiry", LocalDateTime.now().plusDays(7).format(ISO_FORMATTER));
                    }
                }

                if (visualizationTracking && metadata.containsKey("hasVisualization")) {
                    metadata.put("visualizationTracked", true);
                    trackVisualizationPattern(metadata);
                }
            }
            
        } catch (Exception e) {
            log.error("[StudioQueryVectorService] 후처리 실패", e);
        }
    }
    
    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        filters.put("documentType", getDocumentType());
        
        if (cacheSimilarQueries) {
            filters.put("includeCached", true);
        }
        
        return filters;
    }

    public void storeQueryRequest(StudioQueryRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId() != null ? request.getUserId() : "anonymous");
            metadata.put("queryType", request.getQueryType() != null ? request.getQueryType() : "GENERAL");
            // Limit query length to avoid embedding context overflow
            String safeQuery = request.getQuery() != null ?
                request.getQuery().substring(0, Math.min(500, request.getQuery().length())) : "";

            metadata.put("naturalLanguageQuery", safeQuery);
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "studio_query_request");
            metadata.put("requestId", UUID.randomUUID().toString());

            String queryText = String.format(
                "사용자 %s의 자연어 질의: %s (유형: %s)",
                request.getUserId() != null ? request.getUserId() : "anonymous",
                safeQuery,
                request.getQueryType() != null ? request.getQueryType() : "GENERAL"
            );
            
            Document queryDoc = new Document(queryText, metadata);
            storeDocument(queryDoc);

        } catch (Exception e) {
            log.error("[StudioQueryVectorService] 질의 요청 저장 실패", e);
            throw new VectorStoreException("질의 요청 저장 실패: " + e.getMessage(), e);
        }
    }

    public void storeQueryResult(StudioQueryRequest request, StudioQueryResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId() != null ? request.getUserId() : "anonymous");
            metadata.put("queryType", request.getQueryType() != null ? request.getQueryType() : "GENERAL");
            metadata.put("originalQuery", request.getQuery() != null ? request.getQuery() : "");
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "studio_query_result");
            metadata.put("confidenceScore", response.getConfidenceScore());

            metadata.put("hasAnswer", response.getNaturalLanguageAnswer() != null);
            metadata.put("hasVisualization", response.getVisualizationData() != null);
            metadata.put("hasRecommendations", response.getRecommendations() != null && !response.getRecommendations().isEmpty());
            metadata.put("analysisResultCount", response.getAnalysisResults() != null ? response.getAnalysisResults().size() : 0);

            if (response.getRecommendations() != null) {
                List<String> recommendationTypes = response.getRecommendations().stream()
                    .map(r -> r.getType())
                    .distinct()
                    .collect(Collectors.toList());
                metadata.put("recommendationTypes", recommendationTypes);
                metadata.put("recommendationCount", response.getRecommendations().size());
            }

            if (response.getVisualizationData() != null) {
                metadata.put("nodeCount", response.getVisualizationData().getNodes().size());
                metadata.put("edgeCount", response.getVisualizationData().getEdges().size());
                metadata.put("visualizationType", response.getVisualizationData().getGraphType());
            }
            
            // Limit text length to avoid embedding context overflow
            String safeQuery = request.getQuery() != null ?
                request.getQuery().substring(0, Math.min(200, request.getQuery().length())) : "";
            String safeAnswer = response.getNaturalLanguageAnswer() != null ?
                response.getNaturalLanguageAnswer().substring(0, Math.min(300, response.getNaturalLanguageAnswer().length())) : "답변 없음";

            String resultText = String.format(
                "질의 '%s'에 대한 분석 결과: %s (신뢰도: %.1f)",
                safeQuery,
                safeAnswer,
                response.getConfidenceScore()
            );
            
            Document resultDoc = new Document(resultText, metadata);
            storeDocument(resultDoc);

            if (visualizationTracking && response.getVisualizationData() != null) {
                storeVisualizationData(request, response.getVisualizationData());
            }

        } catch (Exception e) {
            log.error("[StudioQueryVectorService] 분석 결과 저장 실패", e);
            throw new VectorStoreException("분석 결과 저장 실패: " + e.getMessage(), e);
        }
    }

    private void storeVisualizationData(StudioQueryRequest request, StudioQueryResponse.VisualizationData vizData) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("userId", request.getUserId() != null ? request.getUserId() : "anonymous");
            metadata.put("originalQuery", request.getQuery() != null ? request.getQuery() : "");
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "studio_visualization");
            metadata.put("visualizationType", vizData.getGraphType() != null ? vizData.getGraphType() : "UNKNOWN");
            metadata.put("nodeCount", vizData.getNodes() != null ? vizData.getNodes().size() : 0);
            metadata.put("edgeCount", vizData.getEdges() != null ? vizData.getEdges().size() : 0);

            if (vizData.getNodes() != null && !vizData.getNodes().isEmpty()) {
                Map<String, Long> nodeTypes = vizData.getNodes().stream()
                    .filter(node -> node.getType() != null)
                    .collect(Collectors.groupingBy(
                        node -> node.getType(),
                        Collectors.counting()
                    ));
                metadata.put("nodeTypes", nodeTypes);
            }

            if (vizData.getEdges() != null && !vizData.getEdges().isEmpty()) {
                Map<String, Long> edgeTypes = vizData.getEdges().stream()
                    .filter(edge -> edge.getType() != null)
                    .collect(Collectors.groupingBy(
                        edge -> edge.getType(),
                        Collectors.counting()
                    ));
                metadata.put("edgeTypes", edgeTypes);
            }

            int nodeCount = vizData.getNodes() != null ? vizData.getNodes().size() : 0;
            int edgeCount = vizData.getEdges() != null ? vizData.getEdges().size() : 0;
            String graphType = vizData.getGraphType() != null ? vizData.getGraphType() : "UNKNOWN";

            String vizText = String.format(
                "시각화 데이터: %d개 노드, %d개 엣지로 구성된 %s 타입 그래프",
                nodeCount,
                edgeCount,
                graphType
            );
            
            Document vizDoc = new Document(vizText, metadata);
            storeDocument(vizDoc);
            
        } catch (Exception e) {
            log.error("[StudioQueryVectorService] 시각화 데이터 저장 실패", e);
        }
    }

    public void storeFeedback(String queryId, boolean isHelpful, String feedback) {
        try {
            String safeQueryId = queryId != null ? queryId : "unknown";
            // Limit feedback length to avoid embedding context overflow
            String safeFeedback = feedback != null ?
                feedback.substring(0, Math.min(500, feedback.length())) : "";

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("queryId", safeQueryId);
            metadata.put("isHelpful", isHelpful);
            metadata.put("feedbackText", safeFeedback);
            metadata.put("feedbackTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "studio_query_feedback");

            String feedbackCategory = categorizeFeedback(safeFeedback);
            metadata.put("feedbackCategory", feedbackCategory);

            List<String> improvementPoints = extractImprovementPoints(safeFeedback);
            if (!improvementPoints.isEmpty()) {
                metadata.put("improvementPoints", improvementPoints);
                metadata.put("hasImprovementSuggestions", true);
            }

            String feedbackText = String.format(
                "질의 %s에 대한 피드백: %s - %s",
                safeQueryId,
                isHelpful ? "도움됨" : "도움안됨",
                safeFeedback
            );
            
            Document feedbackDoc = new Document(feedbackText, metadata);
            storeDocument(feedbackDoc);

        } catch (Exception e) {
            log.error("[StudioQueryVectorService] 피드백 저장 실패", e);
            throw new VectorStoreException("피드백 저장 실패: " + e.getMessage(), e);
        }
    }

    private String classifyQueryType(String content) {
        if (content == null) return "UNKNOWN";
        
        for (Map.Entry<String, Pattern> entry : QUERY_TYPE_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                return entry.getKey();
            }
        }
        
        return "GENERAL_QUERY";
    }

    private String analyzeQueryIntent(String content) {
        if (content == null) return "UNKNOWN";
        
        for (Map.Entry<String, Pattern> entry : INTENT_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                return entry.getKey();
            }
        }
        
        return "INFORMATION_SEEKING";
    }

    private QueryComplexity evaluateQueryComplexity(String content, Map<String, Object> metadata) {
        QueryComplexity complexity = new QueryComplexity();
        double score = 0.0;
        List<String> factors = new ArrayList<>();

        if (content.length() > 200) {
            score += 20.0;
            factors.add("긴 질의");
        }

        long conditionCount = Arrays.stream(content.split("\\s+"))
            .filter(word -> word.matches("그리고|또는|and|or|하지만|but"))
            .count();
        if (conditionCount > 2) {
            score += 15.0 * conditionCount;
            factors.add("복수 조건");
        }

        Map<String, List<String>> entities = (Map<String, List<String>>) metadata.get("entities");
        if (entities != null) {
            int totalEntities = entities.values().stream()
                .mapToInt(List::size)
                .sum();
            if (totalEntities > 3) {
                score += 10.0 * totalEntities;
                factors.add("다수 엔티티");
            }
        }

        if (content.contains("기간") || content.contains("동안") || content.contains("부터")) {
            score += 15.0;
            factors.add("시간 범위");
        }

        if (content.contains("통계") || content.contains("평균") || content.contains("합계")) {
            score += 20.0;
            factors.add("집계 연산");
        }
        
        complexity.setScore(Math.min(score, 100.0));
        complexity.setFactors(factors);
        
        if (score >= 70) complexity.setLevel("HIGH");
        else if (score >= 40) complexity.setLevel("MEDIUM");
        else complexity.setLevel("LOW");
        
        return complexity;
    }

    private Set<String> extractKeywords(String content) {
        Set<String> keywords = new HashSet<>();
        
        if (content == null) return keywords;

        String[] importantTerms = {
            "권한", "사용자", "역할", "정책", "접근", "보안", "감사", "승인",
            "거부", "허용", "관리자", "그룹", "리소스", "API", "데이터", "시스템"
        };
        
        for (String term : importantTerms) {
            if (content.contains(term)) {
                keywords.add(term);
            }
        }
        
        return keywords;
    }

    private Map<String, List<String>> extractEntities(String content) {
        Map<String, List<String>> entities = new HashMap<>();
        entities.put("users", new ArrayList<>());
        entities.put("roles", new ArrayList<>());
        entities.put("resources", new ArrayList<>());
        
        if (content == null) return entities;

        Pattern userPattern = Pattern.compile("\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}\\b|\\buser[0-9]+\\b");
        userPattern.matcher(content).results()
            .forEach(match -> entities.get("users").add(match.group()));

        Pattern rolePattern = Pattern.compile("\\bROLE_[A-Z_]+\\b|\\b(Admin|Manager|User|Guest|Operator)\\b");
        rolePattern.matcher(content).results()
            .forEach(match -> entities.get("roles").add(match.group()));

        Pattern resourcePattern = Pattern.compile("/[a-zA-Z0-9/_-]+|\\b[a-zA-Z0-9]+\\.[a-zA-Z0-9]+\\b");
        resourcePattern.matcher(content).results()
            .forEach(match -> entities.get("resources").add(match.group()));
        
        return entities;
    }

    private TimeContext analyzeTimeContext(String content) {
        TimeContext context = new TimeContext();
        
        if (content == null) {
            context.setType("CURRENT");
            return context;
        }
        
        if (content.contains("현재") || content.contains("지금")) {
            context.setType("CURRENT");
        } else if (content.contains("오늘")) {
            context.setType("TODAY");
            context.setRange("1_DAY");
        } else if (content.contains("어제")) {
            context.setType("YESTERDAY");
            context.setRange("1_DAY");
        } else if (content.contains("이번주") || content.contains("주간")) {
            context.setType("THIS_WEEK");
            context.setRange("7_DAYS");
        } else if (content.contains("이번달") || content.contains("월간")) {
            context.setType("THIS_MONTH");
            context.setRange("30_DAYS");
        } else if (content.contains("작년") || content.contains("연간")) {
            context.setType("THIS_YEAR");
            context.setRange("365_DAYS");
        } else {
            context.setType("UNSPECIFIED");
        }
        
        return context;
    }

    private String evaluateSecuritySensitivity(String content, Map<String, Object> metadata) {
        double sensitivityScore = 0.0;

        String[] sensitiveKeywords = {
            "관리자", "admin", "root", "sudo", "password", "비밀번호",
            "key", "token", "secret", "credential", "인증", "authentication"
        };
        
        for (String keyword : sensitiveKeywords) {
            if (content.toLowerCase().contains(keyword.toLowerCase())) {
                sensitivityScore += 20.0;
            }
        }

        String queryType = (String) metadata.get("queryType");
        if ("PERMISSION_QUERY".equals(queryType) || "SECURITY_QUERY".equals(queryType)) {
            sensitivityScore += 30.0;
        }

        if (content.contains("변경") || content.contains("수정") || content.contains("삭제")) {
            sensitivityScore += 25.0;
        }
        
        if (sensitivityScore >= 70) return "HIGH";
        if (sensitivityScore >= 40) return "MEDIUM";
        return "LOW";
    }

    private String generateQuerySignature(Map<String, Object> metadata) {
        StringBuilder signature = new StringBuilder();
        
        signature.append(metadata.getOrDefault("queryType", "UNKNOWN"));
        signature.append("-");
        signature.append(metadata.getOrDefault("queryIntent", "UNKNOWN"));
        signature.append("-");
        signature.append(metadata.getOrDefault("complexityLevel", "UNKNOWN"));
        
        if ("HIGH".equals(metadata.get("securitySensitivity"))) {
            signature.append("-SENSITIVE");
        }
        
        if (Boolean.TRUE.equals(metadata.get("hasVisualization"))) {
            signature.append("-VIZ");
        }
        
        return signature.toString();
    }

    private void trackVisualizationPattern(Map<String, Object> metadata) {
        
        metadata.put("vizPatternTracked", true);
        metadata.put("vizTrackingTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
    }

    private String categorizeFeedback(String feedback) {
        if (feedback == null) return "GENERAL";
        
        String lowerFeedback = feedback.toLowerCase();
        
        if (lowerFeedback.contains("정확") || lowerFeedback.contains("accurate")) {
            return "ACCURACY";
        } else if (lowerFeedback.contains("빠르") || lowerFeedback.contains("느리") || lowerFeedback.contains("speed")) {
            return "PERFORMANCE";
        } else if (lowerFeedback.contains("이해") || lowerFeedback.contains("명확") || lowerFeedback.contains("clear")) {
            return "CLARITY";
        } else if (lowerFeedback.contains("도움") || lowerFeedback.contains("유용") || lowerFeedback.contains("useful")) {
            return "USEFULNESS";
        } else if (lowerFeedback.contains("시각화") || lowerFeedback.contains("그래프") || lowerFeedback.contains("visualization")) {
            return "VISUALIZATION";
        }
        
        return "GENERAL";
    }

    private List<String> extractImprovementPoints(String feedback) {
        List<String> points = new ArrayList<>();
        
        if (feedback == null) return points;

        Pattern suggestionPattern = Pattern.compile("(더 |좀 더 |보다 )([가-힣a-zA-Z]+)(하면|했으면|해주|하게)");
        suggestionPattern.matcher(feedback).results()
            .forEach(match -> points.add(match.group()));

        if (feedback.contains("부족") || feedback.contains("없") || feedback.contains("안")) {
            points.add("부족한 부분 개선 필요");
        }
        
        return points;
    }

    private static class QueryComplexity {
        private String level;
        private double score;
        private List<String> factors;
        
        public String getLevel() { return level; }
        public void setLevel(String level) { this.level = level; }
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public List<String> getFactors() { return factors; }
        public void setFactors(List<String> factors) { this.factors = factors; }
    }
    
    private static class TimeContext {
        private String type;
        private String range;
        
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getRange() { return range; }
        public void setRange(String range) { this.range = range; }
    }

    public void storeQuery(String query, String queryType) {
        try {
            // Limit query length to avoid embedding context overflow
            String safeQuery = query != null ?
                query.substring(0, Math.min(500, query.length())) : "";
            String safeQueryType = queryType != null ? queryType : "GENERAL";

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", "studio_query");
            metadata.put("queryType", safeQueryType);
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));

            String text = String.format("Studio Query [%s]: %s", safeQueryType, safeQuery);
            Document doc = new Document(text, metadata);
            storeDocument(doc);
            
                    } catch (Exception e) {
            log.error("Studio 쿼리 저장 실패", e);
        }
    }

    public List<Document> findSimilarQueries(String query, int topK) {
        Map<String, Object> filters = new HashMap<>();
        filters.put("documentType", "studio_query");
        filters.put("topK", topK);
        return searchSimilar(query, filters);
    }

    public void storeQueryResult(String queryId, String result) {
        try {
            // Limit result length to avoid embedding context overflow
            String safeQueryId = queryId != null ? queryId : "unknown";
            String safeResult = result != null ?
                result.substring(0, Math.min(1000, result.length())) : "";

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", "studio_query_result");
            metadata.put("queryId", safeQueryId);
            metadata.put("queryType", "QUERY_RESULT");
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));

            Document doc = new Document(safeResult, metadata);
            storeDocument(doc);
            
                    } catch (Exception e) {
            log.error("Studio 쿼리 결과 저장 실패", e);
        }
    }
}