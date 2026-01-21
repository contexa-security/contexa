package io.contexa.contexaiam.aiam.labs.policy;

import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.domain.dto.AiGeneratedPolicyDraftDto;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;

@Slf4j
public class PolicyGenerationVectorService extends AbstractVectorLabService {
    
    @Value("${spring.ai.policy.confidence-threshold:0.8}")
    private double confidenceThreshold;
    
    @Value("${spring.ai.policy.policy-learning:true}")
    private boolean policyLearning;
    
    @Value("${spring.ai.policy.conflict-detection:true}")
    private boolean conflictDetection;
    
    @Value("${spring.ai.policy.compliance-validation:true}")
    private boolean complianceValidation;
    
    @Value("${spring.ai.policy.streaming-support:true}")
    private boolean streamingSupport;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private static final Map<String, Pattern> POLICY_TYPE_PATTERNS = Map.of(
        "ACCESS_CONTROL", Pattern.compile("access|permission|authorization|접근|권한|인가", Pattern.CASE_INSENSITIVE),
        "DATA_PROTECTION", Pattern.compile("data|privacy|encryption|데이터|개인정보|암호화", Pattern.CASE_INSENSITIVE),
        "COMPLIANCE", Pattern.compile("compliance|regulation|audit|준수|규정|감사", Pattern.CASE_INSENSITIVE),
        "SECURITY", Pattern.compile("security|threat|vulnerability|보안|위협|취약", Pattern.CASE_INSENSITIVE),
        "OPERATIONAL", Pattern.compile("operation|process|workflow|운영|프로세스|워크플로", Pattern.CASE_INSENSITIVE),
        "RESOURCE_MANAGEMENT", Pattern.compile("resource|quota|limit|리소스|할당|제한", Pattern.CASE_INSENSITIVE),
        "IDENTITY_MANAGEMENT", Pattern.compile("identity|user|account|신원|사용자|계정", Pattern.CASE_INSENSITIVE),
        "NETWORK", Pattern.compile("network|firewall|routing|네트워크|방화벽|라우팅", Pattern.CASE_INSENSITIVE)
    );

    private static final Map<String, Pattern> POLICY_EFFECT_PATTERNS = Map.of(
        "ALLOW", Pattern.compile("allow|permit|grant|enable|허용|승인|부여|활성", Pattern.CASE_INSENSITIVE),
        "DENY", Pattern.compile("deny|block|reject|disable|거부|차단|금지|비활성", Pattern.CASE_INSENSITIVE),
        "CONDITIONAL", Pattern.compile("if|when|condition|unless|조건|경우|제외", Pattern.CASE_INSENSITIVE),
        "REQUIRE", Pattern.compile("require|must|mandatory|force|요구|필수|강제", Pattern.CASE_INSENSITIVE)
    );

    private static final Map<String, Pattern> POLICY_SCOPE_PATTERNS = Map.of(
        "ORGANIZATION", Pattern.compile("organization|company|enterprise|조직|회사|기업", Pattern.CASE_INSENSITIVE),
        "DEPARTMENT", Pattern.compile("department|division|team|부서|팀|부문", Pattern.CASE_INSENSITIVE),
        "PROJECT", Pattern.compile("project|application|service|프로젝트|애플리케이션|서비스", Pattern.CASE_INSENSITIVE),
        "USER", Pattern.compile("user|individual|person|사용자|개인", Pattern.CASE_INSENSITIVE),
        "ROLE", Pattern.compile("role|group|position|역할|그룹|직위", Pattern.CASE_INSENSITIVE),
        "RESOURCE", Pattern.compile("resource|asset|object|리소스|자산|객체", Pattern.CASE_INSENSITIVE),
        "GLOBAL", Pattern.compile("global|all|entire|전체|모든|전역", Pattern.CASE_INSENSITIVE),
        "CUSTOM", Pattern.compile("custom|specific|special|맞춤|특정|특별", Pattern.CASE_INSENSITIVE)
    );
    
    @Autowired
    public PolicyGenerationVectorService(StandardVectorStoreService standardVectorStoreService,
                                        @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        super(standardVectorStoreService, vectorStoreMetrics);
    }
    
    @Override
    protected String getLabName() {
        return "PolicyGeneration";
    }
    
    @Override
    protected String getDocumentType() {
        return "policy_generation";
    }
    
    @Override
    protected Document enrichLabSpecificMetadata(Document document) {
        Map<String, Object> metadata = new HashMap<>(document.getMetadata());
        
        try {
            
            Set<String> policyTypes = classifyPolicyTypes(document.getText());
            metadata.put("policyTypes", new ArrayList<>(policyTypes));
            metadata.put("multiTypePolic", policyTypes.size() > 1);

            PolicyEffect effect = analyzePolicyEffect(document.getText());
            metadata.put("policyEffect", effect.getEffect());
            metadata.put("effectStrength", effect.getStrength());
            metadata.put("isConditional", effect.isConditional());

            Set<String> scopes = identifyPolicyScopes(document.getText());
            metadata.put("policyScopes", new ArrayList<>(scopes));
            metadata.put("scopeLevel", determineScopeLevel(scopes));

            PolicyComplexity complexity = evaluatePolicyComplexity(document.getText(), metadata);
            metadata.put("complexityScore", complexity.getScore());
            metadata.put("complexityLevel", complexity.getLevel());
            metadata.put("complexityFactors", complexity.getFactors());

            RolePermissionAnalysis rolePermAnalysis = extractRolePermissions(document.getText());
            metadata.put("extractedRoles", rolePermAnalysis.getRoles());
            metadata.put("extractedPermissions", rolePermAnalysis.getPermissions());
            metadata.put("rolePermissionMapping", rolePermAnalysis.getMappings());

            ConditionAnalysis conditions = analyzeConditions(document.getText());
            metadata.put("hasConditions", conditions.hasConditions());
            metadata.put("conditionTypes", conditions.getTypes());
            metadata.put("conditionComplexity", conditions.getComplexity());

            if (conflictDetection) {
                ConflictDetection conflicts = detectPolicyConflicts(metadata);
                metadata.put("hasConflicts", conflicts.hasConflicts());
                metadata.put("conflictTypes", conflicts.getTypes());
                metadata.put("conflictSeverity", conflicts.getSeverity());
            }

            if (complianceValidation) {
                ComplianceValidation compliance = validateCompliance(metadata);
                metadata.put("isCompliant", compliance.isCompliant());
                metadata.put("complianceIssues", compliance.getIssues());
                metadata.put("complianceScore", compliance.getScore());
            }

            PolicyQualityScore qualityScore = calculatePolicyQuality(metadata);
            metadata.put("policyQualityScore", qualityScore.getScore());
            metadata.put("qualityLevel", qualityScore.getLevel());
            metadata.put("qualityIndicators", qualityScore.getIndicators());

            String policySignature = generatePolicySignature(metadata);
            metadata.put("policySignature", policySignature);

            if (policyLearning) {
                PolicyPattern pattern = extractPolicyPattern(metadata);
                metadata.put("policyPattern", pattern.getPattern());
                metadata.put("patternConfidence", pattern.getConfidence());
                metadata.put("isReusablePattern", pattern.isReusable());
            }

            metadata.put("enrichmentVersion", "2.0");
            metadata.put("enrichedByService", "PolicyGenerationVectorService");
            metadata.put("analysisTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            
            return new Document(document.getText(), metadata);
            
        } catch (Exception e) {
            log.error("[PolicyGenerationVectorService] 메타데이터 강화 실패", e);
            metadata.put("enrichmentError", e.getMessage());
            return new Document(document.getText(), metadata);
        }
    }
    
    @Override
    protected void validateLabSpecificDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();

        if (!metadata.containsKey("organizationId") && 
            !metadata.containsKey("policyName") && 
            !metadata.containsKey("naturalLanguageQuery")) {
            throw new IllegalArgumentException(
                "Policy Generation 문서는 organizationId, policyName, naturalLanguageQuery 중 최소 하나는 포함해야 합니다");
        }

        String text = document.getText();
        if (text == null || text.trim().length() < 10) {
            throw new IllegalArgumentException("정책 내용이 너무 짧습니다 (최소 10자 필요)");
        }

        if (text.length() > 10000) {
            throw new IllegalArgumentException("정책 내용이 너무 깁니다 (최대 10000자)");
        }
    }
    
    @Override
    protected void postProcessDocument(Document document, OperationType operationType) {
        try {
            Map<String, Object> metadata = document.getMetadata();
            
            if (operationType == OperationType.STORE) {
                
                Double qualityScore = (Double) metadata.get("policyQualityScore");
                if (qualityScore != null && qualityScore >= confidenceThreshold) {
                                        metadata.put("highQualityPolicy", true);
                    metadata.put("cacheablePolicy", true);
                    cacheHighQualityPolicy(metadata);
                }

                if (Boolean.TRUE.equals(metadata.get("hasConflicts"))) {
                    log.warn("[PolicyGenerationVectorService] 정책 충돌 감지: {}", 
                            metadata.get("conflictTypes"));
                    metadata.put("conflictAlert", true);
                }

                if (Boolean.FALSE.equals(metadata.get("isCompliant"))) {
                    log.warn("[PolicyGenerationVectorService] 규정 준수 문제: {}", 
                            metadata.get("complianceIssues"));
                    metadata.put("complianceAlert", true);
                }

                if (Boolean.TRUE.equals(metadata.get("isReusablePattern"))) {
                                        learnPolicyPattern(metadata);
                }
            }
            
        } catch (Exception e) {
            log.error("[PolicyGenerationVectorService] 후처리 실패", e);
        }
    }
    
    @Override
    protected Map<String, Object> getLabSpecificFilters() {
        Map<String, Object> filters = new HashMap<>();
        filters.put("labName", getLabName());
        filters.put("documentType", getDocumentType());
        
        if (policyLearning) {
            filters.put("includePolicyLearning", true);
        }
        if (conflictDetection) {
            filters.put("includeConflictDetection", true);
        }
        if (complianceValidation) {
            filters.put("includeComplianceValidation", true);
        }
        if (streamingSupport) {
            filters.put("includeStreamingSupport", true);
        }
        
        return filters;
    }

    public void storePolicyGenerationRequest(PolicyGenerationRequest request) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("organizationId", request.getOrganizationId());
            metadata.put("naturalLanguageQuery", request.getNaturalLanguageQuery());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "policy_generation_request");
            metadata.put("requestId", UUID.randomUUID().toString());

            if (request.getAvailableItems() != null) {
                metadata.put("availableRoles", request.getAvailableItems().roles() != null ? 
                        request.getAvailableItems().roles().size() : 0);
                metadata.put("availablePermissions", request.getAvailableItems().permissions() != null ? 
                        request.getAvailableItems().permissions().size() : 0);
                metadata.put("availableConditions", request.getAvailableItems().conditions() != null ? 
                        request.getAvailableItems().conditions().size() : 0);
            }

            metadata.put("streamingEnabled", request.isStreamingRequired());
            
            String requestText = String.format(
                "정책 생성 요청: '%s' (조직=%s, 역할=%d개, 권한=%d개, 조건=%d개, 스트리밍=%s)",
                request.getNaturalLanguageQuery(),
                request.getOrganizationId(),
                metadata.get("availableRoles"),
                metadata.get("availablePermissions"),
                metadata.get("availableConditions"),
                request.isStreamingRequired()
            );
            
            Document requestDoc = new Document(requestText, metadata);
            storeDocument(requestDoc);

        } catch (Exception e) {
            log.error("[PolicyGenerationVectorService] 정책 생성 요청 저장 실패", e);
            throw new VectorStoreException("정책 생성 요청 저장 실패: " + e.getMessage(), e);
        }
    }

    public void storeGeneratedPolicy(PolicyGenerationRequest request, AiGeneratedPolicyDraftDto policyDto) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("organizationId", request.getOrganizationId());
            metadata.put("originalQuery", request.getNaturalLanguageQuery());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "generated_policy");
            metadata.put("policyId", UUID.randomUUID().toString());

            BusinessPolicyDto policy = policyDto.policyData();
            if (policy != null) {
                metadata.put("policyName", policy.getPolicyName());
                metadata.put("policyDescription", policy.getDescription());
                metadata.put("policyEffect", policy.getEffect());
                metadata.put("isConditional", policy.isConditional());

                metadata.put("roleCount", policy.getRoleIds() != null ? policy.getRoleIds().size() : 0);
                metadata.put("permissionCount", policy.getPermissionIds() != null ? policy.getPermissionIds().size() : 0);
                metadata.put("conditionCount", policy.getConditions() != null ? policy.getConditions().size() : 0);
            }

            metadata.put("hasRoleMapping", policyDto.roleIdToNameMap() != null && !policyDto.roleIdToNameMap().isEmpty());
            metadata.put("hasPermissionMapping", policyDto.permissionIdToNameMap() != null && !policyDto.permissionIdToNameMap().isEmpty());
            metadata.put("hasConditionMapping", policyDto.conditionIdToNameMap() != null && !policyDto.conditionIdToNameMap().isEmpty());
            
            String policyText = String.format(
                "AI 생성 정책: '%s' - %s (효과=%s, 조건부=%s, 역할=%d개, 권한=%d개)",
                policy != null ? policy.getPolicyName() : "Unknown",
                policy != null ? policy.getDescription() : "No description",
                policy != null ? policy.getEffect() : "UNKNOWN",
                policy != null ? policy.isConditional() : false,
                metadata.get("roleCount"),
                metadata.get("permissionCount")
            );
            
            Document policyDoc = new Document(policyText, metadata);
            storeDocument(policyDoc);

            storePolicyMappingDetails(policyDto, metadata);

        } catch (Exception e) {
            log.error("[PolicyGenerationVectorService] AI 생성 정책 저장 실패", e);
            throw new VectorStoreException("AI 생성 정책 저장 실패: " + e.getMessage(), e);
        }
    }

    public void storeStreamingProgress(String requestId, String chunk, double progress) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("requestId", requestId);
            metadata.put("chunkData", chunk);
            metadata.put("progress", progress);
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "policy_streaming_progress");
            
            String progressText = String.format(
                "정책 생성 진행 [%s]: %.1f%% 완료",
                requestId,
                progress * 100
            );
            
            Document progressDoc = new Document(progressText, metadata);
            storeDocument(progressDoc);
            
        } catch (Exception e) {
            log.error("스트리밍 진행 상황 저장 실패", e);
        }
    }

    public void storePolicyFeedback(String policyId, boolean approved, String feedback) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("policyId", policyId);
            metadata.put("approved", approved);
            metadata.put("feedbackText", feedback);
            metadata.put("feedbackTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
            metadata.put("documentType", "policy_feedback");

            FeedbackAnalysis analysis = analyzePolicyFeedback(feedback, approved);
            metadata.put("feedbackCategory", analysis.getCategory());
            metadata.put("improvementAreas", analysis.getImprovementAreas());
            metadata.put("satisfactionLevel", analysis.getSatisfactionLevel());
            
            String feedbackText = String.format(
                "정책 피드백 [%s]: %s - %s",
                policyId,
                approved ? "승인됨" : "거부됨",
                feedback
            );
            
            Document feedbackDoc = new Document(feedbackText, metadata);
            storeDocument(feedbackDoc);

            if (policyLearning) {
                updatePolicyLearning(metadata);
            }

        } catch (Exception e) {
            log.error("[PolicyGenerationVectorService] 정책 피드백 저장 실패", e);
            throw new VectorStoreException("정책 피드백 저장 실패: " + e.getMessage(), e);
        }
    }

    private void storePolicyMappingDetails(AiGeneratedPolicyDraftDto policyDto, Map<String, Object> baseMetadata) {
        
        if (policyDto.roleIdToNameMap() != null) {
            policyDto.roleIdToNameMap().forEach((id, name) -> {
                try {
                    Map<String, Object> roleMetadata = new HashMap<>(baseMetadata);
                    roleMetadata.put("mappingType", "ROLE");
                    roleMetadata.put("mappingId", id);
                    roleMetadata.put("mappingName", name);
                    roleMetadata.put("documentType", "policy_role_mapping");
                    
                    Document roleDoc = new Document(
                        String.format("역할 매핑: ID=%s → 이름=%s", id, name),
                        roleMetadata
                    );
                    storeDocument(roleDoc);
                } catch (Exception e) {
                    log.error("역할 매핑 저장 실패: {}", id, e);
                }
            });
        }

        if (policyDto.permissionIdToNameMap() != null) {
            policyDto.permissionIdToNameMap().forEach((id, name) -> {
                try {
                    Map<String, Object> permMetadata = new HashMap<>(baseMetadata);
                    permMetadata.put("mappingType", "PERMISSION");
                    permMetadata.put("mappingId", id);
                    permMetadata.put("mappingName", name);
                    permMetadata.put("documentType", "policy_permission_mapping");
                    
                    Document permDoc = new Document(
                        String.format("권한 매핑: ID=%s → 이름=%s", id, name),
                        permMetadata
                    );
                    storeDocument(permDoc);
                } catch (Exception e) {
                    log.error("권한 매핑 저장 실패: {}", id, e);
                }
            });
        }
    }

    private Set<String> classifyPolicyTypes(String content) {
        Set<String> types = new HashSet<>();
        
        if (content == null) return types;
        
        for (Map.Entry<String, Pattern> entry : POLICY_TYPE_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                types.add(entry.getKey());
            }
        }
        
        if (types.isEmpty()) {
            types.add("GENERAL");
        }
        
        return types;
    }

    private PolicyEffect analyzePolicyEffect(String content) {
        PolicyEffect effect = new PolicyEffect();
        
        if (content == null) {
            effect.setEffect("UNKNOWN");
            effect.setStrength(0.0);
            effect.setConditional(false);
            return effect;
        }

        for (Map.Entry<String, Pattern> entry : POLICY_EFFECT_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                effect.setEffect(entry.getKey());
                break;
            }
        }

        if (POLICY_EFFECT_PATTERNS.get("CONDITIONAL").matcher(content).find()) {
            effect.setConditional(true);
        }

        if ("DENY".equals(effect.getEffect()) || "REQUIRE".equals(effect.getEffect())) {
            effect.setStrength(0.9);
        } else if ("ALLOW".equals(effect.getEffect())) {
            effect.setStrength(0.7);
        } else {
            effect.setStrength(0.5);
        }
        
        return effect;
    }

    private Set<String> identifyPolicyScopes(String content) {
        Set<String> scopes = new HashSet<>();
        
        if (content == null) return scopes;
        
        for (Map.Entry<String, Pattern> entry : POLICY_SCOPE_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(content).find()) {
                scopes.add(entry.getKey());
            }
        }
        
        if (scopes.isEmpty()) {
            scopes.add("DEFAULT");
        }
        
        return scopes;
    }

    private String determineScopeLevel(Set<String> scopes) {
        if (scopes.contains("GLOBAL")) return "GLOBAL";
        if (scopes.contains("ORGANIZATION")) return "ORGANIZATION";
        if (scopes.contains("DEPARTMENT")) return "DEPARTMENT";
        if (scopes.contains("PROJECT")) return "PROJECT";
        if (scopes.contains("ROLE")) return "ROLE";
        if (scopes.contains("USER")) return "USER";
        return "DEFAULT";
    }

    private PolicyComplexity evaluatePolicyComplexity(String content, Map<String, Object> metadata) {
        PolicyComplexity complexity = new PolicyComplexity();
        double score = 0.0;
        List<String> factors = new ArrayList<>();

        List<String> types = (List<String>) metadata.get("policyTypes");
        if (types != null && types.size() > 2) {
            score += 20.0;
            factors.add("다중 정책 유형");
        }

        if (Boolean.TRUE.equals(metadata.get("isConditional"))) {
            score += 25.0;
            factors.add("조건부 정책");
        }

        List<String> scopes = (List<String>) metadata.get("policyScopes");
        if (scopes != null && scopes.size() > 3) {
            score += 15.0;
            factors.add("다중 범위");
        }

        if (content != null && content.length() > 500) {
            score += 10.0;
            factors.add("긴 정책 설명");
        }

        Integer roleCount = (Integer) metadata.get("roleCount");
        Integer permCount = (Integer) metadata.get("permissionCount");
        if (roleCount != null && roleCount > 5) {
            score += 15.0;
            factors.add("다수 역할");
        }
        if (permCount != null && permCount > 10) {
            score += 15.0;
            factors.add("다수 권한");
        }
        
        complexity.setScore(Math.min(score, 100.0));
        complexity.setFactors(factors);
        
        if (score >= 70) complexity.setLevel("HIGH");
        else if (score >= 40) complexity.setLevel("MEDIUM");
        else complexity.setLevel("LOW");
        
        return complexity;
    }

    private RolePermissionAnalysis extractRolePermissions(String content) {
        RolePermissionAnalysis analysis = new RolePermissionAnalysis();
        Set<String> roles = new HashSet<>();
        Set<String> permissions = new HashSet<>();
        Map<String, List<String>> mappings = new HashMap<>();
        
        if (content == null) {
            analysis.setRoles(new ArrayList<>());
            analysis.setPermissions(new ArrayList<>());
            analysis.setMappings(mappings);
            return analysis;
        }

        Pattern rolePattern = Pattern.compile("ROLE_[A-Z_]+|[A-Z][a-z]+(?:Admin|Manager|User|Viewer)");
        rolePattern.matcher(content).results()
            .forEach(match -> roles.add(match.group()));

        Pattern permPattern = Pattern.compile("(READ|WRITE|DELETE|EXECUTE|CREATE|UPDATE|VIEW|MANAGE)_[A-Z_]+");
        permPattern.matcher(content).results()
            .forEach(match -> permissions.add(match.group()));
        
        analysis.setRoles(new ArrayList<>(roles));
        analysis.setPermissions(new ArrayList<>(permissions));
        analysis.setMappings(mappings);
        
        return analysis;
    }

    private ConditionAnalysis analyzeConditions(String content) {
        ConditionAnalysis conditions = new ConditionAnalysis();
        List<String> types = new ArrayList<>();
        
        if (content == null) {
            conditions.setHasConditions(false);
            conditions.setTypes(types);
            conditions.setComplexity("NONE");
            return conditions;
        }

        if (content.contains("time") || content.contains("hour") || content.contains("시간")) {
            types.add("TIME_BASED");
        }

        if (content.contains("location") || content.contains("geo") || content.contains("위치")) {
            types.add("LOCATION_BASED");
        }

        if (content.contains("attribute") || content.contains("property") || content.contains("속성")) {
            types.add("ATTRIBUTE_BASED");
        }
        
        conditions.setHasConditions(!types.isEmpty());
        conditions.setTypes(types);
        
        if (types.size() > 2) conditions.setComplexity("HIGH");
        else if (types.size() > 0) conditions.setComplexity("MEDIUM");
        else conditions.setComplexity("NONE");
        
        return conditions;
    }

    private ConflictDetection detectPolicyConflicts(Map<String, Object> metadata) {
        ConflictDetection conflicts = new ConflictDetection();
        List<String> types = new ArrayList<>();

        String effect = (String) metadata.get("policyEffect");
        if ("ALLOW".equals(effect) && metadata.get("policyTypes") != null) {
            List<String> policyTypes = (List<String>) metadata.get("policyTypes");
            if (policyTypes.contains("SECURITY") && policyTypes.contains("ACCESS_CONTROL")) {
                types.add("EFFECT_CONFLICT");
            }
        }

        List<String> scopes = (List<String>) metadata.get("policyScopes");
        if (scopes != null && scopes.contains("USER") && scopes.contains("GLOBAL")) {
            types.add("SCOPE_CONFLICT");
        }
        
        conflicts.setHasConflicts(!types.isEmpty());
        conflicts.setTypes(types);
        conflicts.setSeverity(types.isEmpty() ? "NONE" : types.size() > 1 ? "HIGH" : "MEDIUM");
        
        return conflicts;
    }

    private ComplianceValidation validateCompliance(Map<String, Object> metadata) {
        ComplianceValidation compliance = new ComplianceValidation();
        List<String> issues = new ArrayList<>();
        double score = 1.0;

        if (metadata.get("policyName") == null) {
            issues.add("정책 이름 누락");
            score -= 0.2;
        }
        
        if (metadata.get("policyDescription") == null) {
            issues.add("정책 설명 누락");
            score -= 0.1;
        }

        String effect = (String) metadata.get("policyEffect");
        if ("UNKNOWN".equals(effect)) {
            issues.add("정책 효과 불명확");
            score -= 0.3;
        }
        
        compliance.setCompliant(issues.isEmpty());
        compliance.setIssues(issues);
        compliance.setScore(Math.max(score, 0.0));
        
        return compliance;
    }

    private PolicyQualityScore calculatePolicyQuality(Map<String, Object> metadata) {
        PolicyQualityScore qualityScore = new PolicyQualityScore();
        double score = 0.0;
        List<String> indicators = new ArrayList<>();

        if (metadata.get("policyName") != null && metadata.get("policyDescription") != null) {
            score += 30.0;
            indicators.add("완전한 정책 정보");
        }

        String effect = (String) metadata.get("policyEffect");
        if (effect != null && !"UNKNOWN".equals(effect)) {
            score += 25.0;
            indicators.add("명확한 정책 효과");
        }

        String complexityLevel = (String) metadata.get("complexityLevel");
        if ("MEDIUM".equals(complexityLevel)) {
            score += 20.0;
            indicators.add("적절한 복잡도");
        } else if ("LOW".equals(complexityLevel)) {
            score += 15.0;
        }

        if (!Boolean.TRUE.equals(metadata.get("hasConflicts"))) {
            score += 15.0;
            indicators.add("충돌 없음");
        }

        if (Boolean.TRUE.equals(metadata.get("isCompliant"))) {
            score += 10.0;
            indicators.add("규정 준수");
        }
        
        qualityScore.setScore(score / 100.0);
        qualityScore.setIndicators(indicators);
        
        if (score >= 85) qualityScore.setLevel("EXCELLENT");
        else if (score >= 70) qualityScore.setLevel("GOOD");
        else if (score >= 50) qualityScore.setLevel("FAIR");
        else qualityScore.setLevel("POOR");
        
        return qualityScore;
    }

    private String generatePolicySignature(Map<String, Object> metadata) {
        StringBuilder signature = new StringBuilder("POL");
        
        String effect = (String) metadata.get("policyEffect");
        if (effect != null) {
            signature.append("-").append(effect.substring(0, Math.min(3, effect.length())));
        }
        
        String scopeLevel = (String) metadata.get("scopeLevel");
        if (scopeLevel != null) {
            signature.append("-").append(scopeLevel.substring(0, Math.min(3, scopeLevel.length())));
        }
        
        Boolean conditional = (Boolean) metadata.get("isConditional");
        if (Boolean.TRUE.equals(conditional)) {
            signature.append("-COND");
        }
        
        signature.append("-").append(System.currentTimeMillis() % 10000);
        
        return signature.toString();
    }

    private PolicyPattern extractPolicyPattern(Map<String, Object> metadata) {
        PolicyPattern pattern = new PolicyPattern();
        
        List<String> types = (List<String>) metadata.get("policyTypes");
        String effect = (String) metadata.get("policyEffect");
        String scope = (String) metadata.get("scopeLevel");
        
        String patternKey = String.join("_", types != null ? types : List.of("UNKNOWN")) + 
                           "_" + effect + "_" + scope;
        
        pattern.setPattern(patternKey);
        pattern.setConfidence(0.8); 
        pattern.setReusable(metadata.get("policyQualityScore") != null && 
                           (Double) metadata.get("policyQualityScore") > 0.7);
        
        return pattern;
    }

    private void cacheHighQualityPolicy(Map<String, Object> metadata) {
                metadata.put("cachedAt", LocalDateTime.now().format(ISO_FORMATTER));
        metadata.put("cacheExpiry", LocalDateTime.now().plusDays(30).format(ISO_FORMATTER));
    }

    private void learnPolicyPattern(Map<String, Object> metadata) {
                metadata.put("patternLearned", true);
        metadata.put("learnedAt", LocalDateTime.now().format(ISO_FORMATTER));
    }

    private FeedbackAnalysis analyzePolicyFeedback(String feedback, boolean approved) {
        FeedbackAnalysis analysis = new FeedbackAnalysis();
        
        if (feedback == null) {
            analysis.setCategory("GENERAL");
            analysis.setImprovementAreas(new ArrayList<>());
            analysis.setSatisfactionLevel(approved ? "SATISFIED" : "UNSATISFIED");
            return analysis;
        }
        
        String lower = feedback.toLowerCase();
        List<String> improvements = new ArrayList<>();

        if (lower.contains("permission") || lower.contains("권한")) {
            analysis.setCategory("PERMISSION");
        } else if (lower.contains("role") || lower.contains("역할")) {
            analysis.setCategory("ROLE");
        } else if (lower.contains("condition") || lower.contains("조건")) {
            analysis.setCategory("CONDITION");
        } else {
            analysis.setCategory("GENERAL");
        }

        if (lower.contains("complex") || lower.contains("복잡")) {
            improvements.add("복잡도 감소");
        }
        if (lower.contains("unclear") || lower.contains("불명확")) {
            improvements.add("명확성 향상");
        }
        if (lower.contains("conflict") || lower.contains("충돌")) {
            improvements.add("충돌 해결");
        }
        
        analysis.setImprovementAreas(improvements);

        if (approved) {
            if (lower.contains("excellent") || lower.contains("perfect") || lower.contains("완벽")) {
                analysis.setSatisfactionLevel("VERY_SATISFIED");
            } else {
                analysis.setSatisfactionLevel("SATISFIED");
            }
        } else {
            if (lower.contains("terrible") || lower.contains("worst") || lower.contains("최악")) {
                analysis.setSatisfactionLevel("VERY_UNSATISFIED");
            } else {
                analysis.setSatisfactionLevel("UNSATISFIED");
            }
        }
        
        return analysis;
    }

    private void updatePolicyLearning(Map<String, Object> metadata) {
                metadata.put("learningUpdated", true);
        metadata.put("updateTimestamp", LocalDateTime.now().format(ISO_FORMATTER));
    }

    private static class PolicyEffect {
        private String effect;
        private double strength;
        private boolean conditional;
        
        public String getEffect() { return effect; }
        public void setEffect(String effect) { this.effect = effect; }
        public double getStrength() { return strength; }
        public void setStrength(double strength) { this.strength = strength; }
        public boolean isConditional() { return conditional; }
        public void setConditional(boolean conditional) { this.conditional = conditional; }
    }
    
    private static class PolicyComplexity {
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
    
    private static class RolePermissionAnalysis {
        private List<String> roles;
        private List<String> permissions;
        private Map<String, List<String>> mappings;
        
        public List<String> getRoles() { return roles; }
        public void setRoles(List<String> roles) { this.roles = roles; }
        public List<String> getPermissions() { return permissions; }
        public void setPermissions(List<String> permissions) { this.permissions = permissions; }
        public Map<String, List<String>> getMappings() { return mappings; }
        public void setMappings(Map<String, List<String>> mappings) { this.mappings = mappings; }
    }
    
    private static class ConditionAnalysis {
        private boolean hasConditions;
        private List<String> types;
        private String complexity;
        
        public boolean hasConditions() { return hasConditions; }
        public void setHasConditions(boolean hasConditions) { this.hasConditions = hasConditions; }
        public List<String> getTypes() { return types; }
        public void setTypes(List<String> types) { this.types = types; }
        public String getComplexity() { return complexity; }
        public void setComplexity(String complexity) { this.complexity = complexity; }
    }
    
    private static class ConflictDetection {
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
    
    private static class ComplianceValidation {
        private boolean compliant;
        private List<String> issues;
        private double score;
        
        public boolean isCompliant() { return compliant; }
        public void setCompliant(boolean compliant) { this.compliant = compliant; }
        public List<String> getIssues() { return issues; }
        public void setIssues(List<String> issues) { this.issues = issues; }
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
    }
    
    private static class PolicyQualityScore {
        private double score;
        private String level;
        private List<String> indicators;
        
        public double getScore() { return score; }
        public void setScore(double score) { this.score = score; }
        public String getLevel() { return level; }
        public void setLevel(String level) { this.level = level; }
        public List<String> getIndicators() { return indicators; }
        public void setIndicators(List<String> indicators) { this.indicators = indicators; }
    }
    
    private static class PolicyPattern {
        private String pattern;
        private double confidence;
        private boolean reusable;
        
        public String getPattern() { return pattern; }
        public void setPattern(String pattern) { this.pattern = pattern; }
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        public boolean isReusable() { return reusable; }
        public void setReusable(boolean reusable) { this.reusable = reusable; }
    }
    
    private static class FeedbackAnalysis {
        private String category;
        private List<String> improvementAreas;
        private String satisfactionLevel;
        
        public String getCategory() { return category; }
        public void setCategory(String category) { this.category = category; }
        public List<String> getImprovementAreas() { return improvementAreas; }
        public void setImprovementAreas(List<String> improvementAreas) { this.improvementAreas = improvementAreas; }
        public String getSatisfactionLevel() { return satisfactionLevel; }
        public void setSatisfactionLevel(String satisfactionLevel) { this.satisfactionLevel = satisfactionLevel; }
    }

    public void storePolicyRequest(PolicyContext context) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", "policy_request");
            metadata.put("organizationId", context.getOrganizationId());
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            
            String text = String.format("정책 생성 요청: Organization=%s", context.getOrganizationId());
            Document doc = new Document(text, metadata);
            storeDocument(doc);
            
                    } catch (Exception e) {
            log.error("정책 요청 저장 실패", e);
        }
    }

    public List<Document> findSimilarPolicies(String query, int topK) {
        Map<String, Object> filters = new HashMap<>();
        filters.put("documentType", "policy_generation");
        filters.put("topK", topK);
        return searchSimilar(query, filters);
    }

    public void storePolicyResult(String requestId, String result) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("documentType", "policy_result");
            metadata.put("requestId", requestId);
            metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            
            Document doc = new Document(result, metadata);
            storeDocument(doc);
            
                    } catch (Exception e) {
            log.error("정책 결과 저장 실패", e);
        }
    }
}