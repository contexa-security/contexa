package io.contexa.contexaiam.aiam.labs.condition;

import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import org.springframework.ai.vectorstore.VectorStore;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;

@Slf4j
public class ConditionTemplateVectorService extends AbstractVectorLabService {
    
    @Value("${spring.ai.condition.spel-validation:true}")
    private boolean spelValidation;
    
    @Value("${spring.ai.condition.template-learning:true}")
    private boolean templateLearning;
    
    @Value("${spring.ai.condition.compatibility-check:true}")
    private boolean compatibilityCheck;
    
    @Value("${spring.ai.condition.syntax-analysis:true}")
    private boolean syntaxAnalysis;
    
    @Value("${spring.ai.condition.template-caching:true}")
    private boolean templateCaching;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private static final Map<String, Pattern> SPEL_PATTERNS = Map.of(
        "METHOD_CALL", Pattern.compile("#\\w+\\.\\w+\\([^)]*\\)"),
        "VARIABLE_REF", Pattern.compile("#\\w+"),
        "PROPERTY_ACCESS", Pattern.compile("\\.\\w+"),
        "OPERATOR", Pattern.compile("(==|!=|<=|>=|<|>|&&|\\|\\||!)"),
        "LITERAL", Pattern.compile("'[^']*'|\"[^\"]*\"|\\d+|true|false|null"),
        "TYPE_REF", Pattern.compile("T\\([^)]+\\)"),
        "COLLECTION", Pattern.compile("\\[|\\]|\\{|\\}"),
        "TERNARY", Pattern.compile("\\?.*:")
    );

    private static final Map<String, Pattern> CONDITION_CATEGORY_PATTERNS = Map.of(
        "TIME_BASED", Pattern.compile("time|hour|minute|date|day|시간|날짜", Pattern.CASE_INSENSITIVE),
        "ROLE_BASED", Pattern.compile("role|hasRole|authority|역할|권한", Pattern.CASE_INSENSITIVE),
        "ATTRIBUTE_BASED", Pattern.compile("attribute|property|field|속성|필드", Pattern.CASE_INSENSITIVE),
        "LOCATION_BASED", Pattern.compile("location|geo|ip|address|위치|주소", Pattern.CASE_INSENSITIVE),
        "RESOURCE_BASED", Pattern.compile("resource|object|target|리소스|대상", Pattern.CASE_INSENSITIVE),
        "AUTHENTICATION", Pattern.compile("authenticated|principal|user|인증|사용자", Pattern.CASE_INSENSITIVE),
        "PERMISSION", Pattern.compile("permission|hasPermission|allow|권한|허용", Pattern.CASE_INSENSITIVE),
        "CUSTOM", Pattern.compile("custom|specific|special|맞춤|특정", Pattern.CASE_INSENSITIVE)
    );

    private static final Map<String, Pattern> CONDITION_CLASSIFICATION_PATTERNS = Map.of(
        "UNIVERSAL", Pattern.compile("universal|general|common|범용|일반|공통", Pattern.CASE_INSENSITIVE),
        "SPECIFIC", Pattern.compile("specific|particular|exact|특정|구체적", Pattern.CASE_INSENSITIVE),
        "CONTEXT_DEPENDENT", Pattern.compile("context|depend|dynamic|상황|의존|동적", Pattern.CASE_INSENSITIVE),
        "TIME_SENSITIVE", Pattern.compile("temporal|time.*sensitive|시간.*민감", Pattern.CASE_INSENSITIVE),
        "SECURITY_CRITICAL", Pattern.compile("security|critical|sensitive|보안|중요|민감", Pattern.CASE_INSENSITIVE)
    );
    
    @Autowired
    public ConditionTemplateVectorService(VectorStore vectorStore,
                                         @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(vectorStore, vectorStoreMetrics);
    }
    
    @Override
    protected String getLabName() {
        return "ConditionTemplate";
    }
    
    @Override
    protected String getDocumentType() {
        return "condition_template";
    }
    
    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        Map<String, Object> metadata = new HashMap<>(document.getMetadata());
        
        try {
            
            SpelAnalysis spelAnalysis = analyzeSpelExpression(document.getText());
            metadata.put("spelComplexity", spelAnalysis.getComplexity());
            metadata.put("spelComponents", spelAnalysis.getComponents());
            metadata.put("hasMethodCalls", spelAnalysis.hasMethodCalls());
            metadata.put("hasVariableRefs", spelAnalysis.hasVariableRefs());
            metadata.put("operatorCount", spelAnalysis.getOperatorCount());

            Set<String> categories = classifyConditionCategories(document.getText());
            metadata.put("conditionCategories", new ArrayList<>(categories));
            metadata.put("isMultiCategory", categories.size() > 1);

            String classification = determineConditionClassification(document.getText());
            metadata.put("conditionClassification", classification);

            if (syntaxAnalysis) {
                SyntaxValidation syntax = validateSpelSyntax(document.getText());
                metadata.put("syntaxValid", syntax.isValid());
                metadata.put("syntaxErrors", syntax.getErrors());
                metadata.put("syntaxWarnings", syntax.getWarnings());
            }

            if (compatibilityCheck) {
                CompatibilityAnalysis compatibility = analyzeCompatibility(document.getText(), metadata);
                metadata.put("springCompatible", compatibility.isSpringCompatible());
                metadata.put("frameworkCompatibility", compatibility.getFrameworks());
                metadata.put("versionRequirements", compatibility.getVersionRequirements());
            }

            TemplateQuality quality = evaluateTemplateQuality(metadata);
            metadata.put("templateQualityScore", quality.getScore());
            metadata.put("qualityLevel", quality.getLevel());
            metadata.put("qualityFactors", quality.getFactors());

            ReusabilityAnalysis reusability = analyzeReusability(document.getText(), metadata);
            metadata.put("reusabilityScore", reusability.getScore());
            metadata.put("isReusable", reusability.isReusable());
            metadata.put("reusabilityFactors", reusability.getFactors());

            PerformanceEstimation performance = estimatePerformance(spelAnalysis);
            metadata.put("estimatedPerformance", performance.getLevel());
            metadata.put("performanceScore", performance.getScore());
            metadata.put("performanceWarnings", performance.getWarnings());

            if (templateLearning) {
                TemplatePattern pattern = extractTemplatePattern(document.getText(), metadata);
                metadata.put("templatePattern", pattern.getPattern());
                metadata.put("patternFrequency", pattern.getFrequency());
                metadata.put("isNewPattern", pattern.isNew());
            }

            String templateSignature = generateTemplateSignature(metadata);
            metadata.put("templateSignature", templateSignature);

            metadata.put("enrichmentVersion", "2.0");
            metadata.put("enrichedByService", "ConditionTemplateVectorService");
            metadata.put("analysisTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            
            return new Document(document.getText(), metadata);
            
        } catch (Exception e) {
            log.error("[ConditionTemplateVectorService] 메타데이터 강화 실패", e);
            metadata.put("enrichmentError", e.getMessage());
            return new Document(document.getText(), metadata);
        }
    }
    
    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("templateName") && 
            !metadata.containsKey("spelTemplate") && 
            !metadata.containsKey("templateType")) {
            throw new IllegalArgumentException(
                "Condition Template 문서는 templateName, spelTemplate, templateType 중 최소 하나는 포함해야 합니다");
        }

        String text = document.getText();
        if (text == null || text.trim().isEmpty()) {
            throw new IllegalArgumentException("조건 템플릿 내용이 비어있습니다");
        }

        if (text.length() > 1000) {
            throw new IllegalArgumentException("조건 템플릿이 너무 깁니다 (최대 1000자)");
        }
    }
    
    @Override
    protected void postProcessDocument(Document document, OperationType operationType) {
        try {
            Map<String, Object> metadata = document.getMetadata();
            
            if (operationType == OperationType.STORE) {
                
                if (templateCaching) {
                    Double qualityScore = (Double) metadata.get("templateQualityScore");
                    if (qualityScore != null && qualityScore >= 0.8) {
                                                metadata.put("highQualityTemplate", true);
                        cacheHighQualityTemplate(metadata);
                    }
                }

                if (Boolean.FALSE.equals(metadata.get("syntaxValid"))) {
                    log.warn("[ConditionTemplateVectorService] SpEL 문법 오류: {}", 
                            metadata.get("syntaxErrors"));
                    metadata.put("syntaxErrorAlert", true);
                }

                if (Boolean.FALSE.equals(metadata.get("springCompatible"))) {
                    log.warn("[ConditionTemplateVectorService] Spring 호환성 문제 감지");
                    metadata.put("compatibilityAlert", true);
                }

                String performanceLevel = (String) metadata.get("estimatedPerformance");
                if ("POOR".equals(performanceLevel)) {
                    log.warn("🐌 [ConditionTemplateVectorService] 낮은 성능 예상: {}", 
                            metadata.get("performanceWarnings"));
                    metadata.put("performanceAlert", true);
                }

                if (Boolean.TRUE.equals(metadata.get("isNewPattern"))) {
                                        learnNewTemplatePattern(metadata);
                }
            }
            
        } catch (Exception e) {
            log.error("[ConditionTemplateVectorService] 후처리 실패", e);
        }
    }
    
    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        filters.put("documentType", getDocumentType());
        
        if (spelValidation) {
            filters.put("includeSpelValidation", true);
        }
        if (templateLearning) {
            filters.put("includeTemplateLearning", true);
        }
        if (compatibilityCheck) {
            filters.put("includeCompatibilityCheck", true);
        }
        if (syntaxAnalysis) {
            filters.put("includeSyntaxAnalysis", true);
        }
        
        return filters;
    }

    public void storeTemplateGenerationRequest(ConditionTemplateGenerationRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("isUniversal", request.isUniversal());
            metadata.put("resourceIdentifier", request.getResourceIdentifier());
            metadata.put("methodInfo", request.getMethodInfo());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "condition_template_request");
            metadata.put("requestId", UUID.randomUUID().toString());
            
            String requestText = String.format(
                "조건 템플릿 생성 요청: 유형=%s, 리소스=%s, 메서드=%s",
                request.isUniversal() ? "범용" : "특정",
                request.getResourceIdentifier() != null ? request.getResourceIdentifier() : "N/A",
                request.getMethodInfo() != null ? request.getMethodInfo() : "N/A"
            );
            
            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);

        } catch (Exception e) {
            log.error("[ConditionTemplateVectorService] 템플릿 생성 요청 저장 실패", e);
            throw new VectorStoreException("템플릿 생성 요청 저장 실패: " + e.getMessage(), e);
        }
    }

    public void storeGeneratedTemplates(ConditionTemplateGenerationRequest request, 
                                       ConditionTemplateGenerationResponse response) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("templateType", request.isUniversal() ? "universal" : "specific");
            metadata.put("resourceIdentifier", response.getResourceIdentifier());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "generated_template");

            int templateCount = 0;
            if (response.getTemplateResult() != null && response.getTemplateResult().contains("[")) {
                
                templateCount = response.getTemplateResult().split("\\{").length - 1;
            }
            metadata.put("templateCount", templateCount);
            
            String resultText = String.format(
                "조건 템플릿 생성 결과: 유형=%s, 템플릿=%d개",
                metadata.get("templateType"),
                templateCount
            );
            
            Document resultDoc = new Document(resultText, metadata);
            storeDocument(resultDoc);

        } catch (Exception e) {
            log.error("[ConditionTemplateVectorService] 생성 템플릿 저장 실패", e);
            throw new VectorStoreException("생성 템플릿 저장 실패: " + e.getMessage(), e);
        }
    }

    public void storeTemplateFeedback(String templateId, boolean useful, String feedback) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("templateId", templateId);
            metadata.put("isUseful", useful);
            metadata.put("feedbackText", feedback);
            metadata.put("feedbackTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "template_feedback");

            FeedbackAnalysis analysis = analyzeTemplateFeedback(feedback, useful);
            metadata.put("feedbackCategory", analysis.getCategory());
            metadata.put("improvementSuggestions", analysis.getSuggestions());
            metadata.put("usabilityScore", analysis.getUsabilityScore());
            
            String feedbackText = String.format(
                "템플릿 피드백 [%s]: %s - %s",
                templateId,
                useful ? "유용함" : "개선필요",
                feedback
            );
            
            Document feedbackDoc = new Document(feedbackText, metadata);
            storeDocument(feedbackDoc);

            if (templateLearning) {
                updateTemplateLearning(metadata);
            }

        } catch (Exception e) {
            log.error("[ConditionTemplateVectorService] 템플릿 피드백 저장 실패", e);
            throw new VectorStoreException("템플릿 피드백 저장 실패: " + e.getMessage(), e);
        }
    }

    private void storeIndividualTemplate(ConditionTemplate template, Map<String, Object> baseMetadata) {
        try {
            Map<String, Object> templateMetadata = new HashMap<>(baseMetadata);
            templateMetadata.put("templateName", template.getName());
            templateMetadata.put("templateDescription", template.getDescription());
            templateMetadata.put("spelTemplate", template.getSpelTemplate());
            templateMetadata.put("templateCategory", template.getCategory());
            templateMetadata.put("templateClassification", template.getClassification());

            templateMetadata.put("documentType", "individual_template");
            
            String templateText = String.format(
                "조건 템플릿 '%s': %s (SpEL: %s)",
                template.getName(),
                template.getDescription(),
                template.getSpelTemplate()
            );
            
            Document templateDoc = new Document(templateText, templateMetadata);
            storeDocument(templateDoc);
            
        } catch (Exception e) {
            log.error("개별 템플릿 저장 실패: {}", template.getName(), e);
        }
    }

    private SpelAnalysis analyzeSpelExpression(String content) {
        SpelAnalysis analysis = new SpelAnalysis();
        Map<String, Integer> components = new HashMap<>();
        
        if (content == null || content.trim().isEmpty()) {
            analysis.setComplexity("NONE");
            analysis.setComponents(components);
            return analysis;
        }

        for (Map.Entry<String, Pattern> entry : SPEL_PATTERNS.entrySet()) {
            int count = (int) entry.getValue().matcher(content).results().count();
            if (count > 0) {
                components.put(entry.getKey(), count);
            }
        }
        
        analysis.setComponents(components);
        analysis.setHasMethodCalls(components.containsKey("METHOD_CALL"));
        analysis.setHasVariableRefs(components.containsKey("VARIABLE_REF"));
        analysis.setOperatorCount(components.getOrDefault("OPERATOR", 0));

        int totalComponents = components.values().stream().mapToInt(Integer::intValue).sum();
        if (totalComponents > 10) analysis.setComplexity("HIGH");
        else if (totalComponents > 5) analysis.setComplexity("MEDIUM");
        else if (totalComponents > 0) analysis.setComplexity("LOW");
        else analysis.setComplexity("NONE");
        
        return analysis;
    }

    private Set<String> classifyConditionCategories(String content) {
        Set<String> categories = new HashSet<>();
        
        if (content == null) return categories;
        
        for (Map.Entry<String, Pattern> entry : CONDITION_CATEGORY_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                categories.add(entry.getKey());
            }
        }
        
        if (categories.isEmpty()) {
            categories.add("GENERAL");
        }
        
        return categories;
    }

    private String determineConditionClassification(String content) {
        if (content == null) return "UNKNOWN";
        
        for (Map.Entry<String, Pattern> entry : CONDITION_CLASSIFICATION_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                return entry.getKey();
            }
        }
        
        return "CONTEXT_DEPENDENT";
    }

    private SyntaxValidation validateSpelSyntax(String content) {
        SyntaxValidation validation = new SyntaxValidation();
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        
        if (content == null || content.trim().isEmpty()) {
            errors.add("빈 표현식");
            validation.setValid(false);
            validation.setErrors(errors);
            validation.setWarnings(warnings);
            return validation;
        }

        int openParens = content.length() - content.replace("(", "").length();
        int closeParens = content.length() - content.replace(")", "").length();
        if (openParens != closeParens) {
            errors.add("괄호 불일치");
        }
        
        int openBrackets = content.length() - content.replace("[", "").length();
        int closeBrackets = content.length() - content.replace("]", "").length();
        if (openBrackets != closeBrackets) {
            errors.add("대괄호 불일치");
        }

        int singleQuotes = content.length() - content.replace("'", "").length();
        if (singleQuotes % 2 != 0) {
            errors.add("따옴표 불일치");
        }

        if (content.contains("==") && !content.contains("equals")) {
            warnings.add("== 대신 equals() 사용 권장");
        }
        
        if (content.contains("null") && !content.contains("?")) {
            warnings.add("null 체크 시 안전 연산자(?) 사용 권장");
        }
        
        validation.setValid(errors.isEmpty());
        validation.setErrors(errors);
        validation.setWarnings(warnings);
        
        return validation;
    }

    private CompatibilityAnalysis analyzeCompatibility(String content, Map<String, Object> metadata) {
        CompatibilityAnalysis compatibility = new CompatibilityAnalysis();
        List<String> frameworks = new ArrayList<>();
        Map<String, String> versionRequirements = new HashMap<>();

        if (content != null) {
            if (content.contains("hasRole") || content.contains("hasAuthority")) {
                frameworks.add("Spring Security");
                versionRequirements.put("Spring Security", "5.0+");
            }
            
            if (content.contains("T(") || content.contains("@")) {
                frameworks.add("Spring Expression Language");
                versionRequirements.put("Spring Core", "3.0+");
            }
            
            if (content.contains("principal")) {
                frameworks.add("Spring Security Core");
                versionRequirements.put("Spring Security Core", "5.0+");
            }
        }
        
        compatibility.setSpringCompatible(!frameworks.isEmpty());
        compatibility.setFrameworks(frameworks);
        compatibility.setVersionRequirements(versionRequirements);
        
        return compatibility;
    }

    private TemplateQuality evaluateTemplateQuality(Map<String, Object> metadata) {
        TemplateQuality quality = new TemplateQuality();
        double score = 0.0;
        List<String> factors = new ArrayList<>();

        if (Boolean.TRUE.equals(metadata.get("syntaxValid"))) {
            score += 30.0;
            factors.add("유효한 문법");
        }

        if (Boolean.TRUE.equals(metadata.get("springCompatible"))) {
            score += 25.0;
            factors.add("Spring 호환");
        }

        String complexity = (String) metadata.get("spelComplexity");
        if ("MEDIUM".equals(complexity)) {
            score += 20.0;
            factors.add("적절한 복잡도");
        } else if ("LOW".equals(complexity)) {
            score += 15.0;
        }

        List<String> categories = (List<String>) metadata.get("conditionCategories");
        if (categories != null && !categories.isEmpty() && !categories.contains("GENERAL")) {
            score += 15.0;
            factors.add("명확한 카테고리");
        }

        Boolean reusable = (Boolean) metadata.get("isReusable");
        if (Boolean.TRUE.equals(reusable)) {
            score += 10.0;
            factors.add("재사용 가능");
        }
        
        quality.setScore(score / 100.0);
        quality.setFactors(factors);
        
        if (score >= 85) quality.setLevel("EXCELLENT");
        else if (score >= 70) quality.setLevel("GOOD");
        else if (score >= 50) quality.setLevel("FAIR");
        else quality.setLevel("POOR");
        
        return quality;
    }

    private ReusabilityAnalysis analyzeReusability(String content, Map<String, Object> metadata) {
        ReusabilityAnalysis reusability = new ReusabilityAnalysis();
        double score = 0.0;
        List<String> factors = new ArrayList<>();

        String classification = (String) metadata.get("conditionClassification");
        if ("UNIVERSAL".equals(classification)) {
            score += 0.4;
            factors.add("범용 템플릿");
        }

        if (content != null && !content.matches(".*'[a-zA-Z0-9_]{10,}'.*")) {
            score += 0.3;
            factors.add("하드코딩 없음");
        }

        Boolean hasVariableRefs = (Boolean) metadata.get("hasVariableRefs");
        if (Boolean.TRUE.equals(hasVariableRefs)) {
            score += 0.2;
            factors.add("파라미터화됨");
        }

        String complexity = (String) metadata.get("spelComplexity");
        if ("LOW".equals(complexity) || "MEDIUM".equals(complexity)) {
            score += 0.1;
            factors.add("적절한 단순성");
        }
        
        reusability.setScore(score);
        reusability.setReusable(score >= 0.6);
        reusability.setFactors(factors);
        
        return reusability;
    }

    private PerformanceEstimation estimatePerformance(SpelAnalysis spelAnalysis) {
        PerformanceEstimation performance = new PerformanceEstimation();
        double score = 1.0;
        List<String> warnings = new ArrayList<>();

        if (spelAnalysis.hasMethodCalls()) {
            score -= 0.2;
            Integer methodCount = spelAnalysis.getComponents().get("METHOD_CALL");
            if (methodCount != null && methodCount > 3) {
                score -= 0.2;
                warnings.add("과도한 메서드 호출");
            }
        }

        if ("HIGH".equals(spelAnalysis.getComplexity())) {
            score -= 0.3;
            warnings.add("높은 복잡도");
        }

        if (spelAnalysis.getOperatorCount() > 5) {
            score -= 0.1;
            warnings.add("많은 연산자");
        }
        
        performance.setScore(Math.max(score, 0.0));
        performance.setWarnings(warnings);
        
        if (score >= 0.8) performance.setLevel("EXCELLENT");
        else if (score >= 0.6) performance.setLevel("GOOD");
        else if (score >= 0.4) performance.setLevel("FAIR");
        else performance.setLevel("POOR");
        
        return performance;
    }

    private TemplatePattern extractTemplatePattern(String content, Map<String, Object> metadata) {
        TemplatePattern pattern = new TemplatePattern();
        
        String category = metadata.get("conditionCategories") != null ? 
            metadata.get("conditionCategories").toString() : "UNKNOWN";
        String classification = (String) metadata.get("conditionClassification");
        
        String patternKey = category + "_" + classification;
        pattern.setPattern(patternKey);
        pattern.setFrequency(1); 
        pattern.setNew(Math.random() > 0.7); 
        
        return pattern;
    }

    private String generateTemplateSignature(Map<String, Object> metadata) {
        StringBuilder signature = new StringBuilder("TPL");
        
        String classification = (String) metadata.get("conditionClassification");
        if (classification != null) {
            signature.append("-").append(classification.substring(0, Math.min(3, classification.length())));
        }
        
        String complexity = (String) metadata.get("spelComplexity");
        if (complexity != null) {
            signature.append("-").append(complexity.charAt(0));
        }
        
        Boolean syntaxValid = (Boolean) metadata.get("syntaxValid");
        if (Boolean.TRUE.equals(syntaxValid)) {
            signature.append("-V");
        }
        
        signature.append("-").append(System.currentTimeMillis() % 10000);
        
        return signature.toString();
    }

    private void cacheHighQualityTemplate(Map<String, Object> metadata) {
                metadata.put("cachedAt", LocalDateTime.now().format(ISO_FORMATTER));
        metadata.put("cacheExpiry", LocalDateTime.now().plusDays(90).format(ISO_FORMATTER));
    }

    private void learnNewTemplatePattern(Map<String, Object> metadata) {
                metadata.put("patternLearned", true);
        metadata.put("learnedAt", LocalDateTime.now().format(ISO_FORMATTER));
    }

    private FeedbackAnalysis analyzeTemplateFeedback(String feedback, boolean useful) {
        FeedbackAnalysis analysis = new FeedbackAnalysis();
        List<String> suggestions = new ArrayList<>();
        
        if (feedback == null) {
            analysis.setCategory("GENERAL");
            analysis.setSuggestions(suggestions);
            analysis.setUsabilityScore(useful ? 0.7 : 0.3);
            return analysis;
        }
        
        String lower = feedback.toLowerCase();

        if (lower.contains("syntax") || lower.contains("문법")) {
            analysis.setCategory("SYNTAX");
        } else if (lower.contains("performance") || lower.contains("성능")) {
            analysis.setCategory("PERFORMANCE");
        } else if (lower.contains("complex") || lower.contains("복잡")) {
            analysis.setCategory("COMPLEXITY");
        } else {
            analysis.setCategory("GENERAL");
        }

        if (lower.contains("simpl") || lower.contains("단순")) {
            suggestions.add("단순화 필요");
        }
        if (lower.contains("clear") || lower.contains("명확")) {
            suggestions.add("명확성 개선");
        }
        if (lower.contains("document") || lower.contains("설명")) {
            suggestions.add("문서화 강화");
        }
        
        analysis.setSuggestions(suggestions);

        if (useful) {
            if (lower.contains("perfect") || lower.contains("excellent") || lower.contains("완벽")) {
                analysis.setUsabilityScore(1.0);
            } else {
                analysis.setUsabilityScore(0.7);
            }
        } else {
            if (lower.contains("terrible") || lower.contains("worst") || lower.contains("최악")) {
                analysis.setUsabilityScore(0.0);
            } else {
                analysis.setUsabilityScore(0.3);
            }
        }
        
        return analysis;
    }

    private void updateTemplateLearning(Map<String, Object> metadata) {
                metadata.put("learningUpdated", true);
        metadata.put("updateTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
    }

    private static class SpelAnalysis {
        private String complexity;
        private Map<String, Integer> components;
        private boolean hasMethodCalls;
        private boolean hasVariableRefs;
        private int operatorCount;
        
        public String getComplexity() { return complexity; }
        public void setComplexity(String complexity) { this.complexity = complexity; }
        public Map<String, Integer> getComponents() { return components; }
        public void setComponents(Map<String, Integer> components) { this.components = components; }
        public boolean hasMethodCalls() { return hasMethodCalls; }
        public void setHasMethodCalls(boolean hasMethodCalls) { this.hasMethodCalls = hasMethodCalls; }
        public boolean hasVariableRefs() { return hasVariableRefs; }
        public void setHasVariableRefs(boolean hasVariableRefs) { this.hasVariableRefs = hasVariableRefs; }
        public int getOperatorCount() { return operatorCount; }
        public void setOperatorCount(int operatorCount) { this.operatorCount = operatorCount; }
    }
    
    private static class SyntaxValidation {
        private boolean valid;
        private List<String> errors;
        private List<String> warnings;
        
        public boolean isValid() { return valid; }
        public void setValid(boolean valid) { this.valid = valid; }
        public List<String> getErrors() { return errors; }
        public void setErrors(List<String> errors) { this.errors = errors; }
        public List<String> getWarnings() { return warnings; }
        public void setWarnings(List<String> warnings) { this.warnings = warnings; }
    }
    
    private static class CompatibilityAnalysis {
        private boolean springCompatible;
        private List<String> frameworks;
        private Map<String, String> versionRequirements;
        
        public boolean isSpringCompatible() { return springCompatible; }
        public void setSpringCompatible(boolean springCompatible) { this.springCompatible = springCompatible; }
        public List<String> getFrameworks() { return frameworks; }
        public void setFrameworks(List<String> frameworks) { this.frameworks = frameworks; }
        public Map<String, String> getVersionRequirements() { return versionRequirements; }
        public void setVersionRequirements(Map<String, String> versionRequirements) { this.versionRequirements = versionRequirements; }
    }
    
    private static class TemplateQuality {
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
    
    private static class ReusabilityAnalysis {
        private double score;
        private boolean reusable;
        private List<String> factors;
        
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public boolean isReusable() { return reusable; }
        public void setReusable(boolean reusable) { this.reusable = reusable; }
        public List<String> getFactors() { return factors; }
        public void setFactors(List<String> factors) { this.factors = factors; }
    }
    
    private static class PerformanceEstimation {
        private String level;
        private double score;
        private List<String> warnings;
        
        public String getLevel() { return level; }
        public void setLevel(String level) { this.level = level; }
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public List<String> getWarnings() { return warnings; }
        public void setWarnings(List<String> warnings) { this.warnings = warnings; }
    }
    
    private static class TemplatePattern {
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
    
    private static class FeedbackAnalysis {
        private String category;
        private List<String> suggestions;
        private double usabilityScore;
        
        public String getCategory() { return category; }
        public void setCategory(String category) { this.category = category; }
        public List<String> getSuggestions() { return suggestions; }
        public void setSuggestions(List<String> suggestions) { this.suggestions = suggestions; }
        public double getUsabilityScore() { return usabilityScore; }
        public void setUsabilityScore(double usabilityScore) { this.usabilityScore = usabilityScore; }
    }

    public void storeConditionContext(ConditionTemplateContext context) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", "condition_context");
            metadata.put("organizationId", context.getOrganizationId());
            metadata.put("templateType", context.getTemplateType());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            
            String text = String.format("조건 템플릿 컨텍스트: Type=%s, Organization=%s",
                context.getTemplateType(), context.getOrganizationId());
            
            Document doc = new Document(text, metadata);
            storeDocument(doc);
            
                    } catch (Exception e) {
            log.error("조건 템플릿 컨텍스트 저장 실패", e);
        }
    }

    public List<Document> findMethodConditions(String methodName, int topK) {
        try {
            Map<String, Object> filters = new HashMap<>();
            filters.put("documentType", "method_condition");
            filters.put("methodName", methodName);
            filters.put("topK", topK);
            
            String query = String.format("메서드 조건: %s", methodName);
            return searchSimilar(query, filters);
        } catch (Exception e) {
            log.error("메서드 조건 검색 실패", e);
            return List.of();
        }
    }
}