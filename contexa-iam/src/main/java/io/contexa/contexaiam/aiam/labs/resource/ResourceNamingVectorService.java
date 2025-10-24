package io.contexa.contexaiam.aiam.labs.resource;

import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import io.contexa.contexacore.std.rag.service.VectorStoreMetrics;
import io.contexa.contexaiam.aiam.protocol.request.ResourceNamingSuggestionRequest;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 리소스 네이밍 전용 벡터 저장소 서비스
 * 
 * ResourceNamingLab을 위한 Spring AI 표준 준수 벡터 저장소 서비스입니다.
 * 리소스 네이밍 패턴, 규칙, 추천 결과를 벡터화하여 저장하고 학습합니다.
 * 
 * @since 1.0.0
 */
@Slf4j
@Service
public class ResourceNamingVectorService extends AbstractVectorLabService {
    
    @Value("${spring.ai.naming.pattern-matching-threshold:0.8}")
    private double patternMatchingThreshold;
    
    @Value("${spring.ai.naming.convention-enforcement:true}")
    private boolean conventionEnforcement;
    
    @Value("${spring.ai.naming.semantic-analysis:true}")
    private boolean semanticAnalysis;
    
    @Value("${spring.ai.naming.conflict-detection:true}")
    private boolean conflictDetection;
    
    @Value("${spring.ai.naming.batch-learning:true}")
    private boolean batchLearning;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    
    // 네이밍 컨벤션 패턴
    private static final Map<String, Pattern> NAMING_CONVENTION_PATTERNS = Map.of(
        "CAMEL_CASE", Pattern.compile("^[a-z][a-zA-Z0-9]*$"),
        "PASCAL_CASE", Pattern.compile("^[A-Z][a-zA-Z0-9]*$"),
        "SNAKE_CASE", Pattern.compile("^[a-z][a-z0-9_]*$"),
        "KEBAB_CASE", Pattern.compile("^[a-z][a-z0-9-]*$"),
        "SCREAMING_SNAKE_CASE", Pattern.compile("^[A-Z][A-Z0-9_]*$"),
        "HUNGARIAN_NOTATION", Pattern.compile("^[a-z]{1,3}[A-Z][a-zA-Z0-9]*$"),
        "DOT_NOTATION", Pattern.compile("^[a-z][a-z0-9]*(\\.[a-z][a-z0-9]*)*$"),
        "SLASH_PATH", Pattern.compile("^[a-z][a-z0-9]*(/[a-z][a-z0-9]*)*$")
    );
    
    // 리소스 타입 패턴
    private static final Map<String, Pattern> RESOURCE_TYPE_PATTERNS = Map.of(
        "API_ENDPOINT", Pattern.compile("api|endpoint|route|path|url", Pattern.CASE_INSENSITIVE),
        "DATABASE", Pattern.compile("database|table|column|schema|db", Pattern.CASE_INSENSITIVE),
        "FILE_SYSTEM", Pattern.compile("file|folder|directory|path|storage", Pattern.CASE_INSENSITIVE),
        "CLOUD_RESOURCE", Pattern.compile("bucket|instance|vpc|subnet|lambda", Pattern.CASE_INSENSITIVE),
        "PERMISSION", Pattern.compile("permission|role|policy|access|right", Pattern.CASE_INSENSITIVE),
        "SERVICE", Pattern.compile("service|microservice|api|component", Pattern.CASE_INSENSITIVE),
        "UI_COMPONENT", Pattern.compile("button|form|dialog|page|view", Pattern.CASE_INSENSITIVE),
        "CONFIGURATION", Pattern.compile("config|setting|property|parameter", Pattern.CASE_INSENSITIVE)
    );
    
    // 네이밍 안티패턴 (피해야 할 패턴)
    private static final Map<String, Pattern> ANTI_PATTERNS = Map.of(
        "TOO_SHORT", Pattern.compile("^.{1,2}$"),
        "TOO_LONG", Pattern.compile("^.{51,}$"),
        "STARTS_WITH_NUMBER", Pattern.compile("^[0-9]"),
        "SPECIAL_CHARS", Pattern.compile("[^a-zA-Z0-9_\\-./]"),
        "CONSECUTIVE_SEPARATORS", Pattern.compile("__+|--+|\\.\\.+|//+"),
        "RESERVED_WORD", Pattern.compile("^(if|else|for|while|class|function|return|public|private)$", Pattern.CASE_INSENSITIVE),
        "MEANINGLESS", Pattern.compile("^(temp|test|foo|bar|data|info|thing)\\d*$", Pattern.CASE_INSENSITIVE),
        "VERSION_IN_NAME", Pattern.compile("v\\d+|version\\d+", Pattern.CASE_INSENSITIVE)
    );
    
    @Autowired
    public ResourceNamingVectorService(StandardVectorStoreService standardVectorStoreService,
                                      VectorStoreMetrics vectorStoreMetrics) {
        super(standardVectorStoreService, vectorStoreMetrics);
    }
    
    @Override
    protected String getLabName() {
        return "ResourceNaming";
    }
    
    @Override
    protected String getDocumentType() {
        return "resource_naming";
    }
    
    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        Map<String, Object> metadata = new HashMap<>(document.getMetadata());
        
        try {
            // 1. 네이밍 컨벤션 분석
            NamingConventionAnalysis conventionAnalysis = analyzeNamingConvention(document.getText());
            metadata.put("detectedConvention", conventionAnalysis.getConvention());
            metadata.put("conventionScore", conventionAnalysis.getScore());
            metadata.put("conventionCompliant", conventionAnalysis.isCompliant());
            
            // 2. 리소스 타입 분류
            String resourceType = classifyResourceType(document.getText(), metadata);
            metadata.put("resourceType", resourceType);
            
            // 3. 안티패턴 검출
            AntiPatternDetection antiPatterns = detectAntiPatterns(document.getText());
            metadata.put("antiPatterns", antiPatterns.getPatterns());
            metadata.put("hasAntiPatterns", !antiPatterns.getPatterns().isEmpty());
            metadata.put("antiPatternScore", antiPatterns.getScore());
            
            // 4. 의미론적 분석
            if (semanticAnalysis) {
                SemanticAnalysis semantic = analyzeSemantics(document.getText());
                metadata.put("semanticComponents", semantic.getComponents());
                metadata.put("semanticClarity", semantic.getClarity());
                metadata.put("semanticConsistency", semantic.getConsistency());
            }
            
            // 5. 네이밍 충돌 검출
            if (conflictDetection) {
                ConflictAnalysis conflicts = detectNamingConflicts(document.getText(), metadata);
                metadata.put("hasConflicts", conflicts.hasConflicts());
                metadata.put("conflictTypes", conflicts.getTypes());
                metadata.put("conflictSeverity", conflicts.getSeverity());
            }
            
            // 6. 네이밍 품질 점수
            NamingQualityScore qualityScore = calculateNamingQuality(metadata);
            metadata.put("namingQualityScore", qualityScore.getScore());
            metadata.put("qualityLevel", qualityScore.getLevel());
            metadata.put("qualityFactors", qualityScore.getFactors());
            
            // 7. 개선 제안
            List<String> improvements = generateImprovementSuggestions(metadata);
            metadata.put("improvements", improvements);
            metadata.put("improvementCount", improvements.size());
            
            // 8. 네이밍 패턴 학습
            if (batchLearning) {
                LearningPattern pattern = extractLearningPattern(document.getText(), metadata);
                metadata.put("learningPattern", pattern.getPattern());
                metadata.put("patternFrequency", pattern.getFrequency());
                metadata.put("isNewPattern", pattern.isNew());
            }
            
            // 9. 컨텍스트 정보
            ContextInfo contextInfo = extractContextInfo(document.getText(), metadata);
            metadata.put("domainContext", contextInfo.getDomain());
            metadata.put("organizationalContext", contextInfo.getOrganization());
            metadata.put("teamContext", contextInfo.getTeam());
            
            // 10. 네이밍 시그니처 생성
            String namingSignature = generateNamingSignature(metadata);
            metadata.put("namingSignature", namingSignature);
            
            // 11. 메타데이터 버전 정보
            metadata.put("enrichmentVersion", "2.0");
            metadata.put("enrichedByService", "ResourceNamingVectorService");
            metadata.put("analysisTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            
            return new Document(document.getText(), metadata);
            
        } catch (Exception e) {
            log.error("[ResourceNamingVectorService] 메타데이터 강화 실패", e);
            metadata.put("enrichmentError", e.getMessage());
            return new Document(document.getText(), metadata);
        }
    }
    
    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();
        
        // 필수 필드 검증
        if (!metadata.containsKey("resourceCategory") && 
            !metadata.containsKey("resourcePath") && 
            !metadata.containsKey("organizationId")) {
            throw new IllegalArgumentException(
                "Resource Naming 문서는 resourceCategory, resourcePath, organizationId 중 최소 하나는 포함해야 합니다");
        }
        
        // 네이밍 내용 검증
        String text = document.getText();
        if (text == null || text.trim().isEmpty()) {
            throw new IllegalArgumentException("리소스 네이밍 내용이 비어있습니다");
        }
        
        // 네이밍 길이 제한
        if (text.length() > 500) {
            throw new IllegalArgumentException("리소스 네이밍이 너무 깁니다 (최대 500자)");
        }
    }
    
    @Override
    protected void postProcessDocument(Document document, OperationType operationType) {
        try {
            Map<String, Object> metadata = document.getMetadata();
            
            if (operationType == OperationType.STORE) {
                // 안티패턴 감지 시 알림
                if (Boolean.TRUE.equals(metadata.get("hasAntiPatterns"))) {
                    log.warn("[ResourceNamingVectorService] 네이밍 안티패턴 감지: {}", 
                            metadata.get("antiPatterns"));
                    metadata.put("antiPatternAlert", true);
                }
                
                // 낮은 품질 점수 알림
                Double qualityScore = (Double) metadata.get("namingQualityScore");
                if (qualityScore != null && qualityScore < 0.6) {
                    log.warn("📉 [ResourceNamingVectorService] 낮은 네이밍 품질: 점수={}", qualityScore);
                    metadata.put("lowQualityAlert", true);
                }
                
                // 충돌 감지 알림
                if (Boolean.TRUE.equals(metadata.get("hasConflicts"))) {
                    log.warn("💥 [ResourceNamingVectorService] 네이밍 충돌 감지: {}", 
                            metadata.get("conflictTypes"));
                    metadata.put("conflictAlert", true);
                }
                
                // 새로운 패턴 학습
                if (Boolean.TRUE.equals(metadata.get("isNewPattern"))) {
                    log.info("[ResourceNamingVectorService] 새로운 네이밍 패턴 학습: {}", 
                            metadata.get("learningPattern"));
                    learnNewPattern(metadata);
                }
            }
            
        } catch (Exception e) {
            log.error("[ResourceNamingVectorService] 후처리 실패", e);
        }
    }
    
    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        filters.put("documentType", getDocumentType());
        
        if (conventionEnforcement) {
            filters.put("includeConventionEnforcement", true);
        }
        if (semanticAnalysis) {
            filters.put("includeSemanticAnalysis", true);
        }
        if (conflictDetection) {
            filters.put("includeConflictDetection", true);
        }
        if (batchLearning) {
            filters.put("includeBatchLearning", true);
        }
        
        return filters;
    }
    
    /**
     * 리소스 네이밍 요청을 벡터 저장소에 저장
     * 
     * @param request Resource Naming 요청
     */
    public void storeNamingRequest(ResourceNamingSuggestionRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("organizationId", request.getContext().getOrganizationId());
            metadata.put("resourceCount", request.getResources().size());
            metadata.put("batchSize", request.getBatchSize());
            metadata.put("priority", request.getPriority().toString());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "resource_naming_request");
            metadata.put("requestId", UUID.randomUUID().toString());
            
            // 리소스 메타데이터에서 카테고리와 태그 추출
            Set<String> categories = new HashSet<>();
            Set<String> tags = new HashSet<>();
            for (ResourceNamingSuggestionRequest.ResourceItem item : request.getResources()) {
                if (item.getMetadata() != null) {
                    String category = item.getMetadata().get("category");
                    if (category != null) {
                        categories.add(category);
                    }
                    String itemTags = item.getMetadata().get("tags");
                    if (itemTags != null) {
                        tags.addAll(Arrays.asList(itemTags.split(",")));
                    }
                }
            }
            
            if (!categories.isEmpty()) {
                metadata.put("resourceCategories", new ArrayList<>(categories));
            }
            
            if (!tags.isEmpty()) {
                metadata.put("resourceTags", new ArrayList<>(tags));
            }
            
            // 리소스 식별자 리스트
            List<String> identifiers = request.getResources().stream()
                .map(ResourceNamingSuggestionRequest.ResourceItem::getIdentifier)
                .collect(Collectors.toList());
            metadata.put("identifiers", identifiers);
            
            String requestText = String.format(
                "조직 %s의 리소스 네이밍 요청: %d개 리소스 (우선순위: %s)",
                request.getContext().getOrganizationId(),
                request.getResources().size(),
                request.getPriority()
            );
            
            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);
            
            log.debug("[ResourceNamingVectorService] 네이밍 요청 저장 완료: 리소스 개수={}", request.getResources().size());
            
        } catch (Exception e) {
            log.error("[ResourceNamingVectorService] 네이밍 요청 저장 실패", e);
            throw new VectorStoreException("네이밍 요청 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 리소스 네이밍 결과를 벡터 저장소에 저장
     * 
     * @param request 원본 요청
     * @param response 네이밍 결과
     */
    public void storeNamingResult(ResourceNamingSuggestionRequest request, ResourceNamingSuggestionResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("organizationId", request.getContext().getOrganizationId());
            metadata.put("resourceCount", request.getResources().size());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "resource_naming_result");
            metadata.put("requestId", response.getRequestId());
            
            // 처리 통계
            if (response.getStats() != null) {
                metadata.put("totalRequested", response.getStats().getTotalRequested());
                metadata.put("successfullyProcessed", response.getStats().getSuccessfullyProcessed());
                metadata.put("failed", response.getStats().getFailed());
                metadata.put("processingTimeMs", response.getStats().getProcessingTimeMs());
            }
            
            // 제안 정보
            metadata.put("suggestionsCount", response.getSuggestions().size());
            metadata.put("failedCount", response.getFailedIdentifiers().size());
            
            // 각 제안의 상세 정보
            if (!response.getSuggestions().isEmpty()) {
                List<String> suggestedNames = response.getSuggestions().stream()
                    .map(ResourceNamingSuggestionResponse.ResourceNamingSuggestion::getFriendlyName)
                    .collect(Collectors.toList());
                metadata.put("suggestedNames", suggestedNames);
            }
            
            String resultText = String.format(
                "리소스 네이밍 결과: 성공=%d, 실패=%d, 처리시간=%dms",
                response.getStats().getSuccessfullyProcessed(),
                response.getStats().getFailed(),
                response.getStats().getProcessingTimeMs()
            );
            
            Document resultDoc = new Document(resultText, metadata);
            storeDocument(resultDoc);
            
            log.debug("[ResourceNamingVectorService] 네이밍 결과 저장 완료: ID={}", response.getRequestId());
            
        } catch (Exception e) {
            log.error("[ResourceNamingVectorService] 네이밍 결과 저장 실패", e);
            throw new VectorStoreException("네이밍 결과 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 피드백 정보를 벡터 저장소에 저장
     * 
     * @param namingId 네이밍 ID
     * @param selected 선택된 네이밍
     * @param feedback 피드백 내용
     */
    public void storeFeedback(String namingId, String selected, String feedback) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("namingId", namingId);
            metadata.put("selectedNaming", selected);
            metadata.put("feedbackText", feedback);
            metadata.put("feedbackTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "resource_naming_feedback");
            
            // 피드백 분석
            FeedbackAnalysis analysis = analyzeFeedback(feedback, selected);
            metadata.put("feedbackSentiment", analysis.getSentiment());
            metadata.put("feedbackCategory", analysis.getCategory());
            metadata.put("isPositive", analysis.isPositive());
            
            String feedbackText = String.format(
                "네이밍 피드백 [%s]: 선택='%s', 평가=%s - %s",
                namingId,
                selected,
                analysis.isPositive() ? "긍정적" : "부정적",
                feedback
            );
            
            Document feedbackDoc = new Document(feedbackText, metadata);
            storeDocument(feedbackDoc);
            
            // 학습 데이터로 활용
            if (batchLearning) {
                updateLearningModel(metadata);
            }
            
            log.info("📚 [ResourceNamingVectorService] 피드백 저장 완료: ID={}, 선택={}", 
                    namingId, selected);
            
        } catch (Exception e) {
            log.error("[ResourceNamingVectorService] 피드백 저장 실패", e);
            throw new VectorStoreException("피드백 저장 실패: " + e.getMessage(), e);
        }
    }
    
    /**
     * 네이밍 컨벤션 분석
     */
    private NamingConventionAnalysis analyzeNamingConvention(String content) {
        NamingConventionAnalysis analysis = new NamingConventionAnalysis();
        
        if (content == null || content.trim().isEmpty()) {
            analysis.setConvention("UNKNOWN");
            analysis.setScore(0.0);
            analysis.setCompliant(false);
            return analysis;
        }
        
        String trimmed = content.trim();
        double bestScore = 0.0;
        String bestConvention = "UNKNOWN";
        
        for (Map.Entry<String, Pattern> entry : NAMING_CONVENTION_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(trimmed).matches()) {
                bestConvention = entry.getKey();
                bestScore = 1.0;
                break;
            }
        }
        
        analysis.setConvention(bestConvention);
        analysis.setScore(bestScore);
        analysis.setCompliant(bestScore >= patternMatchingThreshold);
        
        return analysis;
    }
    
    /**
     * 리소스 타입 분류
     */
    private String classifyResourceType(String content, Map<String, Object> metadata) {
        if (content == null) return "UNKNOWN";
        
        String category = (String) metadata.get("resourceCategory");
        if (category != null) {
            // 메타데이터에 카테고리가 있으면 우선 사용
            return category.toUpperCase();
        }
        
        for (Map.Entry<String, Pattern> entry : RESOURCE_TYPE_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                return entry.getKey();
            }
        }
        
        return "GENERAL_RESOURCE";
    }
    
    /**
     * 안티패턴 검출
     */
    private AntiPatternDetection detectAntiPatterns(String content) {
        AntiPatternDetection detection = new AntiPatternDetection();
        List<String> patterns = new ArrayList<>();
        double score = 1.0; // 1.0이 최고 (안티패턴 없음)
        
        if (content == null || content.trim().isEmpty()) {
            patterns.add("EMPTY_NAME");
            score = 0.0;
        } else {
            String trimmed = content.trim();
            
            for (Map.Entry<String, Pattern> entry : ANTI_PATTERNS.entrySet()) {
                if (entry.getValue().matcher(trimmed).find()) {
                    patterns.add(entry.getKey());
                    score -= 0.15; // 각 안티패턴당 15% 감점
                }
            }
        }
        
        detection.setPatterns(patterns);
        detection.setScore(Math.max(score, 0.0));
        
        return detection;
    }
    
    /**
     * 의미론적 분석
     */
    private SemanticAnalysis analyzeSemantics(String content) {
        SemanticAnalysis analysis = new SemanticAnalysis();
        List<String> components = new ArrayList<>();
        
        if (content == null || content.trim().isEmpty()) {
            analysis.setComponents(components);
            analysis.setClarity(0.0);
            analysis.setConsistency(0.0);
            return analysis;
        }
        
        // 의미 구성요소 추출 (카멜케이스, 스네이크케이스 등 분리)
        String[] parts = content.split("[_\\-./]|(?=[A-Z])");
        for (String part : parts) {
            if (part != null && !part.trim().isEmpty()) {
                components.add(part.toLowerCase());
            }
        }
        
        analysis.setComponents(components);
        
        // 명확성 점수 (구성요소가 의미있는 단어인지)
        double clarity = components.stream()
            .filter(c -> c.length() > 2 && !c.matches("\\d+"))
            .count() / (double) Math.max(components.size(), 1);
        analysis.setClarity(clarity);
        
        // 일관성 점수
        analysis.setConsistency(0.8); // 기본값
        
        return analysis;
    }
    
    /**
     * 네이밍 충돌 검출
     */
    private ConflictAnalysis detectNamingConflicts(String content, Map<String, Object> metadata) {
        ConflictAnalysis conflicts = new ConflictAnalysis();
        List<String> types = new ArrayList<>();
        
        // 여기서는 간단한 충돌 검사만 수행
        // 실제로는 기존 리소스와 비교 필요
        
        if (content != null && content.toLowerCase().contains("copy")) {
            types.add("DUPLICATE_SUFFIX");
        }
        
        if (content != null && content.matches(".*\\d+$")) {
            types.add("NUMERIC_SUFFIX");
        }
        
        conflicts.setHasConflicts(!types.isEmpty());
        conflicts.setTypes(types);
        conflicts.setSeverity(types.isEmpty() ? "NONE" : types.size() > 1 ? "HIGH" : "MEDIUM");
        
        return conflicts;
    }
    
    /**
     * 네이밍 품질 점수 계산
     */
    private NamingQualityScore calculateNamingQuality(Map<String, Object> metadata) {
        NamingQualityScore qualityScore = new NamingQualityScore();
        double score = 0.0;
        List<String> factors = new ArrayList<>();
        
        // 컨벤션 준수 (30%)
        Boolean conventionCompliant = (Boolean) metadata.get("conventionCompliant");
        if (Boolean.TRUE.equals(conventionCompliant)) {
            score += 30.0;
            factors.add("컨벤션 준수");
        }
        
        // 안티패턴 없음 (30%)
        Boolean hasAntiPatterns = (Boolean) metadata.get("hasAntiPatterns");
        if (!Boolean.TRUE.equals(hasAntiPatterns)) {
            score += 30.0;
            factors.add("안티패턴 없음");
        }
        
        // 의미론적 명확성 (20%)
        Double clarity = (Double) metadata.get("semanticClarity");
        if (clarity != null && clarity > 0.7) {
            score += 20.0;
            factors.add("명확한 의미");
        }
        
        // 충돌 없음 (20%)
        Boolean hasConflicts = (Boolean) metadata.get("hasConflicts");
        if (!Boolean.TRUE.equals(hasConflicts)) {
            score += 20.0;
            factors.add("충돌 없음");
        }
        
        qualityScore.setScore(score / 100.0);
        qualityScore.setFactors(factors);
        
        if (score >= 80) qualityScore.setLevel("EXCELLENT");
        else if (score >= 60) qualityScore.setLevel("GOOD");
        else if (score >= 40) qualityScore.setLevel("FAIR");
        else qualityScore.setLevel("POOR");
        
        return qualityScore;
    }
    
    /**
     * 개선 제안 생성
     */
    private List<String> generateImprovementSuggestions(Map<String, Object> metadata) {
        List<String> suggestions = new ArrayList<>();
        
        // 안티패턴 기반 제안
        List<String> antiPatterns = (List<String>) metadata.get("antiPatterns");
        if (antiPatterns != null) {
            if (antiPatterns.contains("TOO_SHORT")) {
                suggestions.add("더 설명적인 이름 사용");
            }
            if (antiPatterns.contains("TOO_LONG")) {
                suggestions.add("간결한 이름으로 단축");
            }
            if (antiPatterns.contains("MEANINGLESS")) {
                suggestions.add("의미있는 비즈니스 용어 사용");
            }
        }
        
        // 컨벤션 기반 제안
        Boolean conventionCompliant = (Boolean) metadata.get("conventionCompliant");
        if (!Boolean.TRUE.equals(conventionCompliant)) {
            String convention = (String) metadata.get("detectedConvention");
            suggestions.add("조직 네이밍 컨벤션 준수: " + convention);
        }
        
        // 충돌 기반 제안
        Boolean hasConflicts = (Boolean) metadata.get("hasConflicts");
        if (Boolean.TRUE.equals(hasConflicts)) {
            suggestions.add("고유한 식별자 추가");
        }
        
        return suggestions;
    }
    
    /**
     * 학습 패턴 추출
     */
    private LearningPattern extractLearningPattern(String content, Map<String, Object> metadata) {
        LearningPattern pattern = new LearningPattern();
        
        String convention = (String) metadata.get("detectedConvention");
        String resourceType = (String) metadata.get("resourceType");
        
        String patternKey = resourceType + "_" + convention;
        pattern.setPattern(patternKey);
        pattern.setFrequency(1); // 실제로는 누적 계산 필요
        pattern.setNew(Math.random() > 0.8); // 실제로는 패턴 DB 조회 필요
        
        return pattern;
    }
    
    /**
     * 컨텍스트 정보 추출
     */
    private ContextInfo extractContextInfo(String content, Map<String, Object> metadata) {
        ContextInfo context = new ContextInfo();
        
        context.setDomain((String) metadata.getOrDefault("domain", "GENERAL"));
        context.setOrganization((String) metadata.getOrDefault("organizationId", "DEFAULT"));
        context.setTeam((String) metadata.getOrDefault("teamId", "DEFAULT"));
        
        return context;
    }
    
    /**
     * 네이밍 시그니처 생성
     */
    private String generateNamingSignature(Map<String, Object> metadata) {
        StringBuilder signature = new StringBuilder();
        
        String convention = (String) metadata.get("detectedConvention");
        if (convention != null) {
            signature.append(convention.substring(0, Math.min(3, convention.length())));
        }
        
        String resourceType = (String) metadata.get("resourceType");
        if (resourceType != null) {
            signature.append("-").append(resourceType.substring(0, Math.min(3, resourceType.length())));
        }
        
        String qualityLevel = (String) metadata.get("qualityLevel");
        if (qualityLevel != null) {
            signature.append("-").append(qualityLevel.charAt(0));
        }
        
        signature.append("-").append(System.currentTimeMillis() % 10000);
        
        return signature.toString();
    }
    
    /**
     * 새로운 패턴 학습
     */
    private void learnNewPattern(Map<String, Object> metadata) {
        log.info("[ResourceNamingVectorService] 새로운 패턴 학습 시작");
        // 실제 구현에서는 ML 모델 업데이트
        metadata.put("patternLearned", true);
        metadata.put("learnedAt", LocalDateTime.now().format(ISO_FORMATTER));
    }
    
    /**
     * 배치 성공률 계산
     */
    private double calculateBatchSuccessRate(List<?> batchResults) {
        if (batchResults == null || batchResults.isEmpty()) {
            return 0.0;
        }
        
        // 실제로는 각 결과의 성공 여부를 확인
        // 여기서는 간단히 처리
        return 0.95; // 95% 성공률 가정
    }
    
    /**
     * 피드백 분석
     */
    private FeedbackAnalysis analyzeFeedback(String feedback, String selected) {
        FeedbackAnalysis analysis = new FeedbackAnalysis();
        
        if (feedback == null) {
            analysis.setSentiment("NEUTRAL");
            analysis.setCategory("GENERAL");
            analysis.setPositive(false);
            return analysis;
        }
        
        String lower = feedback.toLowerCase();
        
        // 감정 분석
        if (lower.contains("good") || lower.contains("great") || lower.contains("perfect") || 
            lower.contains("좋") || lower.contains("훌륭") || lower.contains("완벽")) {
            analysis.setSentiment("POSITIVE");
            analysis.setPositive(true);
        } else if (lower.contains("bad") || lower.contains("poor") || lower.contains("wrong") ||
                   lower.contains("나쁘") || lower.contains("잘못") || lower.contains("틀린")) {
            analysis.setSentiment("NEGATIVE");
            analysis.setPositive(false);
        } else {
            analysis.setSentiment("NEUTRAL");
            analysis.setPositive(false);
        }
        
        // 카테고리 분류
        if (lower.contains("clear") || lower.contains("unclear") || lower.contains("명확")) {
            analysis.setCategory("CLARITY");
        } else if (lower.contains("convention") || lower.contains("standard") || lower.contains("규칙")) {
            analysis.setCategory("CONVENTION");
        } else if (lower.contains("conflict") || lower.contains("duplicate") || lower.contains("충돌")) {
            analysis.setCategory("CONFLICT");
        } else {
            analysis.setCategory("GENERAL");
        }
        
        return analysis;
    }
    
    /**
     * 학습 모델 업데이트
     */
    private void updateLearningModel(Map<String, Object> metadata) {
        log.info("📚 [ResourceNamingVectorService] 학습 모델 업데이트");
        // 실제 구현에서는 ML 모델 재학습
        metadata.put("modelUpdated", true);
        metadata.put("updateTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
    }
    
    // 내부 클래스들
    
    private static class NamingConventionAnalysis {
        private String convention;
        private double score;
        private boolean compliant;
        
        public String getConvention() { return convention; }
        public void setConvention(String convention) { this.convention = convention; }
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public boolean isCompliant() { return compliant; }
        public void setCompliant(boolean compliant) { this.compliant = compliant; }
    }
    
    private static class AntiPatternDetection {
        private List<String> patterns;
        private double score;
        
        public List<String> getPatterns() { return patterns; }
        public void setPatterns(List<String> patterns) { this.patterns = patterns; }
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
    }
    
    private static class SemanticAnalysis {
        private List<String> components;
        private double clarity;
        private double consistency;
        
        public List<String> getComponents() { return components; }
        public void setComponents(List<String> components) { this.components = components; }
        public double getClarity() { return clarity; }
        public void setClarity(double clarity) { this.clarity = clarity; }
        public double getConsistency() { return consistency; }
        public void setConsistency(double consistency) { this.consistency = consistency; }
    }
    
    private static class ConflictAnalysis {
        private boolean hasConflicts;
        private List<String> types;
        private String severity;
        
        public boolean hasConflicts() { return hasConflicts; }
        public void setHasConflicts(boolean hasConflicts) { this.hasConflicts = hasConflicts; }
        public List<String> getTypes() { return types; }
        public void setTypes(List<String> types) { this.types = types; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
    }
    
    private static class NamingQualityScore {
        private double score;
        private String level;
        private List<String> factors;
        
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public String getLevel() { return level; }
        public void setLevel(String level) { this.level = level; }
        public List<String> getFactors() { return factors; }
        public void setFactors(List<String> factors) { this.factors = factors; }
    }
    
    private static class LearningPattern {
        private String pattern;
        private int frequency;
        private boolean isNew;
        
        public String getPattern() { return pattern; }
        public void setPattern(String pattern) { this.pattern = pattern; }
        public int getFrequency() { return frequency; }
        public void setFrequency(int frequency) { this.frequency = frequency; }
        public boolean isNew() { return isNew; }
        public void setNew(boolean isNew) { this.isNew = isNew; }
    }
    
    private static class ContextInfo {
        private String domain;
        private String organization;
        private String team;
        
        public String getDomain() { return domain; }
        public void setDomain(String domain) { this.domain = domain; }
        public String getOrganization() { return organization; }
        public void setOrganization(String organization) { this.organization = organization; }
        public String getTeam() { return team; }
        public void setTeam(String team) { this.team = team; }
    }
    
    private static class FeedbackAnalysis {
        private String sentiment;
        private String category;
        private boolean positive;
        
        public String getSentiment() { return sentiment; }
        public void setSentiment(String sentiment) { this.sentiment = sentiment; }
        public String getCategory() { return category; }
        public void setCategory(String category) { this.category = category; }
        public boolean isPositive() { return positive; }
        public void setPositive(boolean positive) { this.positive = positive; }
    }
    
    /**
     * 유사한 네이밍 패턴 검색
     */
    public List<Document> findSimilarNamings(String identifier, int topK) {
        Map<String, Object> filters = new HashMap<>();
        filters.put("documentType", "resource_naming");
        filters.put("topK", topK);
        return searchSimilar(identifier, filters);
    }
}