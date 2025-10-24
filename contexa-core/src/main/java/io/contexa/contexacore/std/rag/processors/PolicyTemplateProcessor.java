package io.contexa.contexacore.std.rag.processors;

import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 정책 템플릿 처리 프로세서
 * 
 * 검색된 정책 문서를 분석하여 재사용 가능한 템플릿을 추출하고,
 * 새로운 정책 생성을 위한 패턴과 구조를 식별합니다.
 * 
 * @since 1.0.0
 */
@Component("policyTemplateProcessor")
public class PolicyTemplateProcessor implements DocumentPostProcessor {
    
    @Value("${spring.ai.rag.policy.min-template-score:0.7}")
    private double minTemplateScore;
    
    @Value("${spring.ai.rag.policy.max-templates:10}")
    private int maxTemplates;
    
    @Value("${spring.ai.rag.policy.merge-similar-threshold:0.85}")
    private double mergeSimilarThreshold;
    
    // 정책 패턴 매칭을 위한 정규 표현식
    private static final Pattern CONDITION_PATTERN = Pattern.compile(
        "(?:IF|WHEN|WHERE|GIVEN)\\s+(.+?)\\s+(?:THEN|DO|ALLOW|DENY|GRANT|REVOKE)",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );
    
    private static final Pattern ACTION_PATTERN = Pattern.compile(
        "(?:THEN|DO|MUST|SHALL|SHOULD|CAN|MAY)\\s+(.+?)(?:\\.|;|$)",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern RESOURCE_PATTERN = Pattern.compile(
        "(?:ON|TO|FROM|ACCESS TO|RESOURCE|PATH)\\s+([\\w/\\-\\.\\*]+)",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern ROLE_PATTERN = Pattern.compile(
        "(?:ROLE|USER|GROUP|PRINCIPAL)\\s*[:=]?\\s*([\\w\\-]+)",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public List<Document> process(Query query, List<Document> documents) {
        if (documents.isEmpty()) {
            return documents;
        }
        
        // 1. 정책 템플릿 추출
        List<PolicyTemplate> templates = extractPolicyTemplates(documents);
        
        // 2. 유사 템플릿 병합
        List<PolicyTemplate> mergedTemplates = mergeSimilarTemplates(templates);
        
        // 3. 템플릿 순위 지정
        List<PolicyTemplate> rankedTemplates = rankTemplates(mergedTemplates);
        
        // 4. 문서 강화
        enrichDocumentsWithTemplates(documents, rankedTemplates);
        
        // 5. 템플릿 품질 기준 정렬
        return sortByTemplateQuality(documents);
    }
    
    /**
     * 정책 템플릿 추출
     */
    private List<PolicyTemplate> extractPolicyTemplates(List<Document> documents) {
        List<PolicyTemplate> templates = new ArrayList<>();
        
        for (Document doc : documents) {
            String content = doc.getText();
            if (content == null || content.isEmpty()) {
                continue;
            }
            
            PolicyTemplate template = new PolicyTemplate();
            template.setSourceDocument(doc);
            
            // 정책 구조 추출
            template.setConditions(extractConditions(content));
            template.setActions(extractActions(content));
            template.setResources(extractResources(content));
            template.setRoles(extractRoles(content));
            
            // 정책 유형 식별
            template.setPolicyType(identifyPolicyType(doc));
            
            // 템플릿 점수 계산
            template.setTemplateScore(calculateTemplateScore(template));
            
            // 메타데이터 추출
            extractTemplateMetadata(template, doc);
            
            if (template.getTemplateScore() >= minTemplateScore) {
                templates.add(template);
            }
        }
        
        return templates;
    }
    
    /**
     * 조건 추출
     */
    private List<String> extractConditions(String content) {
        List<String> conditions = new ArrayList<>();
        Matcher matcher = CONDITION_PATTERN.matcher(content);
        
        while (matcher.find()) {
            String condition = matcher.group(1).trim();
            // 정규화 및 파라미터화
            condition = normalizeCondition(condition);
            if (!condition.isEmpty()) {
                conditions.add(condition);
            }
        }
        
        return conditions;
    }
    
    /**
     * 액션 추출
     */
    private List<String> extractActions(String content) {
        List<String> actions = new ArrayList<>();
        Matcher matcher = ACTION_PATTERN.matcher(content);
        
        while (matcher.find()) {
            String action = matcher.group(1).trim();
            action = normalizeAction(action);
            if (!action.isEmpty() && isValidAction(action)) {
                actions.add(action);
            }
        }
        
        return actions;
    }
    
    /**
     * 리소스 추출
     */
    private List<String> extractResources(String content) {
        List<String> resources = new ArrayList<>();
        Matcher matcher = RESOURCE_PATTERN.matcher(content);
        
        while (matcher.find()) {
            String resource = matcher.group(1).trim();
            if (isValidResource(resource)) {
                resources.add(normalizeResource(resource));
            }
        }
        
        return resources.stream().distinct().collect(Collectors.toList());
    }
    
    /**
     * 역할 추출
     */
    private List<String> extractRoles(String content) {
        List<String> roles = new ArrayList<>();
        Matcher matcher = ROLE_PATTERN.matcher(content);
        
        while (matcher.find()) {
            String role = matcher.group(1).trim().toUpperCase();
            if (isValidRole(role)) {
                roles.add(role);
            }
        }
        
        return roles.stream().distinct().collect(Collectors.toList());
    }
    
    /**
     * 정책 유형 식별
     */
    private String identifyPolicyType(Document document) {
        String content = document.getText().toUpperCase();
        Map<String, Object> metadata = document.getMetadata();
        
        // 메타데이터에서 유형 확인
        Object policyType = metadata.get("policyType");
        if (policyType != null) {
            return policyType.toString();
        }
        
        // 내용 기반 유형 추론
        if (content.contains("ACCESS") || content.contains("PERMISSION")) {
            return "ACCESS_CONTROL";
        } else if (content.contains("DATA") && (content.contains("CLASSIFICATION") || content.contains("SENSITIVITY"))) {
            return "DATA_CLASSIFICATION";
        } else if (content.contains("NETWORK") || content.contains("FIREWALL")) {
            return "NETWORK_SECURITY";
        } else if (content.contains("AUTHENTICATION") || content.contains("PASSWORD")) {
            return "AUTHENTICATION";
        } else if (content.contains("AUDIT") || content.contains("LOG")) {
            return "AUDIT_LOGGING";
        } else if (content.contains("COMPLIANCE") || content.contains("REGULATION")) {
            return "COMPLIANCE";
        } else if (content.contains("INCIDENT") || content.contains("RESPONSE")) {
            return "INCIDENT_RESPONSE";
        }
        
        return "GENERAL_POLICY";
    }
    
    /**
     * 템플릿 점수 계산
     */
    private double calculateTemplateScore(PolicyTemplate template) {
        double score = 0.0;
        
        // 구조 완성도 (40%)
        double structureScore = 0.0;
        if (!template.getConditions().isEmpty()) structureScore += 0.25;
        if (!template.getActions().isEmpty()) structureScore += 0.25;
        if (!template.getResources().isEmpty()) structureScore += 0.25;
        if (!template.getRoles().isEmpty()) structureScore += 0.25;
        score += structureScore * 0.4;
        
        // 명확성 (30%)
        double clarityScore = calculateClarityScore(template);
        score += clarityScore * 0.3;
        
        // 재사용성 (20%)
        double reusabilityScore = calculateReusabilityScore(template);
        score += reusabilityScore * 0.2;
        
        // 검증 가능성 (10%)
        double verifiabilityScore = calculateVerifiabilityScore(template);
        score += verifiabilityScore * 0.1;
        
        return Math.min(score, 1.0);
    }
    
    /**
     * 명확성 점수 계산
     */
    private double calculateClarityScore(PolicyTemplate template) {
        double score = 0.0;
        
        // 조건 명확성
        for (String condition : template.getConditions()) {
            if (containsSpecificOperators(condition)) {
                score += 0.2;
            }
        }
        
        // 액션 명확성
        for (String action : template.getActions()) {
            if (isSpecificAction(action)) {
                score += 0.2;
            }
        }
        
        // 리소스 구체성
        for (String resource : template.getResources()) {
            if (!resource.contains("*") && !resource.contains("?")) {
                score += 0.2;
            }
        }
        
        return Math.min(score, 1.0);
    }
    
    /**
     * 재사용성 점수 계산
     */
    private double calculateReusabilityScore(PolicyTemplate template) {
        double score = 0.5; // 기본 점수
        
        // 파라미터화 가능성
        int parameterizableElements = 0;
        parameterizableElements += countParameterizableElements(template.getConditions());
        parameterizableElements += countParameterizableElements(template.getActions());
        
        score += Math.min(parameterizableElements * 0.1, 0.3);
        
        // 일반성
        if ("GENERAL_POLICY".equals(template.getPolicyType()) || 
            "ACCESS_CONTROL".equals(template.getPolicyType())) {
            score += 0.2;
        }
        
        return Math.min(score, 1.0);
    }
    
    /**
     * 검증 가능성 점수 계산
     */
    private double calculateVerifiabilityScore(PolicyTemplate template) {
        double score = 0.0;
        
        // 측정 가능한 조건
        for (String condition : template.getConditions()) {
            if (containsMeasurableCondition(condition)) {
                score += 0.25;
            }
        }
        
        // 감사 가능한 액션
        for (String action : template.getActions()) {
            if (isAuditableAction(action)) {
                score += 0.25;
            }
        }
        
        return Math.min(score, 1.0);
    }
    
    /**
     * 유사 템플릿 병합
     */
    private List<PolicyTemplate> mergeSimilarTemplates(List<PolicyTemplate> templates) {
        List<PolicyTemplate> merged = new ArrayList<>();
        Set<Integer> processedIndices = new HashSet<>();
        
        for (int i = 0; i < templates.size(); i++) {
            if (processedIndices.contains(i)) continue;
            
            PolicyTemplate base = templates.get(i);
            List<PolicyTemplate> similar = new ArrayList<>();
            similar.add(base);
            
            for (int j = i + 1; j < templates.size(); j++) {
                if (processedIndices.contains(j)) continue;
                
                PolicyTemplate candidate = templates.get(j);
                double similarity = calculateTemplateSimilarity(base, candidate);
                
                if (similarity >= mergeSimilarThreshold) {
                    similar.add(candidate);
                    processedIndices.add(j);
                }
            }
            
            if (similar.size() > 1) {
                merged.add(mergeTemplates(similar));
            } else {
                merged.add(base);
            }
            
            processedIndices.add(i);
        }
        
        return merged;
    }
    
    /**
     * 템플릿 유사도 계산
     */
    private double calculateTemplateSimilarity(PolicyTemplate t1, PolicyTemplate t2) {
        double similarity = 0.0;
        
        // 정책 유형 일치
        if (t1.getPolicyType().equals(t2.getPolicyType())) {
            similarity += 0.3;
        }
        
        // 조건 유사도
        similarity += calculateListSimilarity(t1.getConditions(), t2.getConditions()) * 0.25;
        
        // 액션 유사도
        similarity += calculateListSimilarity(t1.getActions(), t2.getActions()) * 0.25;
        
        // 리소스 유사도
        similarity += calculateListSimilarity(t1.getResources(), t2.getResources()) * 0.1;
        
        // 역할 유사도
        similarity += calculateListSimilarity(t1.getRoles(), t2.getRoles()) * 0.1;
        
        return similarity;
    }
    
    /**
     * 리스트 유사도 계산 (Jaccard 계수)
     */
    private double calculateListSimilarity(List<String> list1, List<String> list2) {
        if (list1.isEmpty() && list2.isEmpty()) return 1.0;
        if (list1.isEmpty() || list2.isEmpty()) return 0.0;
        
        Set<String> set1 = new HashSet<>(list1);
        Set<String> set2 = new HashSet<>(list2);
        
        Set<String> intersection = new HashSet<>(set1);
        intersection.retainAll(set2);
        
        Set<String> union = new HashSet<>(set1);
        union.addAll(set2);
        
        return union.isEmpty() ? 0.0 : (double) intersection.size() / union.size();
    }
    
    /**
     * 템플릿 병합
     */
    private PolicyTemplate mergeTemplates(List<PolicyTemplate> templates) {
        PolicyTemplate merged = new PolicyTemplate();
        
        // 가장 높은 점수의 템플릿을 기본으로 사용
        PolicyTemplate best = templates.stream()
            .max(Comparator.comparing(PolicyTemplate::getTemplateScore))
            .orElse(templates.get(0));
        
        merged.setPolicyType(best.getPolicyType());
        merged.setSourceDocument(best.getSourceDocument());
        
        // 모든 요소 병합
        Set<String> allConditions = new HashSet<>();
        Set<String> allActions = new HashSet<>();
        Set<String> allResources = new HashSet<>();
        Set<String> allRoles = new HashSet<>();
        
        for (PolicyTemplate template : templates) {
            allConditions.addAll(template.getConditions());
            allActions.addAll(template.getActions());
            allResources.addAll(template.getResources());
            allRoles.addAll(template.getRoles());
        }
        
        merged.setConditions(new ArrayList<>(allConditions));
        merged.setActions(new ArrayList<>(allActions));
        merged.setResources(new ArrayList<>(allResources));
        merged.setRoles(new ArrayList<>(allRoles));
        
        // 병합된 템플릿 점수 재계산
        merged.setTemplateScore(calculateTemplateScore(merged));
        merged.setMergedCount(templates.size());
        
        return merged;
    }
    
    /**
     * 템플릿 순위 지정
     */
    private List<PolicyTemplate> rankTemplates(List<PolicyTemplate> templates) {
        return templates.stream()
            .sorted((t1, t2) -> {
                // 1차: 템플릿 점수
                int scoreCompare = Double.compare(t2.getTemplateScore(), t1.getTemplateScore());
                if (scoreCompare != 0) return scoreCompare;
                
                // 2차: 병합 횟수 (많이 병합된 템플릿이 더 일반적)
                int mergeCompare = Integer.compare(t2.getMergedCount(), t1.getMergedCount());
                if (mergeCompare != 0) return mergeCompare;
                
                // 3차: 구조 완성도
                return Integer.compare(
                    t2.getConditions().size() + t2.getActions().size(),
                    t1.getConditions().size() + t1.getActions().size()
                );
            })
            .limit(maxTemplates)
            .collect(Collectors.toList());
    }
    
    /**
     * 문서에 템플릿 정보 추가
     */
    private void enrichDocumentsWithTemplates(List<Document> documents, List<PolicyTemplate> templates) {
        Map<Document, PolicyTemplate> documentTemplateMap = new HashMap<>();
        
        // 각 문서에 해당하는 템플릿 매핑
        for (PolicyTemplate template : templates) {
            documentTemplateMap.put(template.getSourceDocument(), template);
        }
        
        for (Document doc : documents) {
            PolicyTemplate template = documentTemplateMap.get(doc);
            Map<String, Object> metadata = doc.getMetadata();
            
            if (template != null) {
                metadata.put("hasTemplate", true);
                metadata.put("templateScore", template.getTemplateScore());
                metadata.put("policyType", template.getPolicyType());
                metadata.put("templateConditions", template.getConditions());
                metadata.put("templateActions", template.getActions());
                metadata.put("templateResources", template.getResources());
                metadata.put("templateRoles", template.getRoles());
                
                if (template.getMergedCount() > 1) {
                    metadata.put("mergedTemplateCount", template.getMergedCount());
                }
            } else {
                metadata.put("hasTemplate", false);
            }
        }
    }
    
    /**
     * 템플릿 품질 기준 정렬
     */
    private List<Document> sortByTemplateQuality(List<Document> documents) {
        return documents.stream()
            .sorted((d1, d2) -> {
                boolean hasTemplate1 = (Boolean) d1.getMetadata().getOrDefault("hasTemplate", false);
                boolean hasTemplate2 = (Boolean) d2.getMetadata().getOrDefault("hasTemplate", false);
                
                if (hasTemplate1 && !hasTemplate2) return -1;
                if (!hasTemplate1 && hasTemplate2) return 1;
                
                if (hasTemplate1) {
                    double score1 = (Double) d1.getMetadata().getOrDefault("templateScore", 0.0);
                    double score2 = (Double) d2.getMetadata().getOrDefault("templateScore", 0.0);
                    return Double.compare(score2, score1);
                }
                
                return 0;
            })
            .collect(Collectors.toList());
    }
    
    // 헬퍼 메서드들
    
    private String normalizeCondition(String condition) {
        return condition.replaceAll("\\s+", " ")
            .replaceAll("\\b\\d+\\b", "${NUMBER}")
            .replaceAll("'[^']*'", "${STRING}")
            .trim();
    }
    
    private String normalizeAction(String action) {
        return action.replaceAll("\\s+", " ")
            .replaceAll("\\b(SHALL|SHOULD|MUST|MAY|CAN)\\b", "")
            .trim();
    }
    
    private String normalizeResource(String resource) {
        return resource.replaceAll("\\\\", "/")
            .toLowerCase()
            .trim();
    }
    
    private boolean isValidAction(String action) {
        return action.length() > 3 && 
               !action.matches("\\d+") &&
               !action.matches("[\\W_]+");
    }
    
    private boolean isValidResource(String resource) {
        return resource.length() > 1 &&
               (resource.matches("[\\w/\\-\\.\\*]+") ||
                resource.matches("\\$\\{[^}]+\\}"));
    }
    
    private boolean isValidRole(String role) {
        return role.length() > 2 &&
               !role.matches("\\d+") &&
               !role.equals("THE") &&
               !role.equals("AND") &&
               !role.equals("OR");
    }
    
    private boolean containsSpecificOperators(String condition) {
        return condition.matches(".*(==|!=|>=|<=|>|<|IN|NOT IN|BETWEEN|LIKE).*");
    }
    
    private boolean isSpecificAction(String action) {
        String upper = action.toUpperCase();
        return upper.contains("GRANT") || upper.contains("DENY") ||
               upper.contains("ALLOW") || upper.contains("REVOKE") ||
               upper.contains("AUDIT") || upper.contains("LOG") ||
               upper.contains("ENCRYPT") || upper.contains("NOTIFY");
    }
    
    private int countParameterizableElements(List<String> elements) {
        return (int) elements.stream()
            .filter(e -> e.contains("${"))
            .count();
    }
    
    private boolean containsMeasurableCondition(String condition) {
        return condition.matches(".*(TIME|DATE|COUNT|SIZE|LIMIT|THRESHOLD|RATE).*");
    }
    
    private boolean isAuditableAction(String action) {
        String upper = action.toUpperCase();
        return upper.contains("LOG") || upper.contains("AUDIT") ||
               upper.contains("RECORD") || upper.contains("TRACK") ||
               upper.contains("MONITOR");
    }
    
    private void extractTemplateMetadata(PolicyTemplate template, Document document) {
        Map<String, Object> metadata = document.getMetadata();
        
        template.setCreatedBy((String) metadata.get("createdBy"));
        template.setCreatedDate((String) metadata.get("createdDate"));
        template.setComplianceFramework((String) metadata.get("complianceFramework"));
        template.setVersion((String) metadata.get("version"));
    }
    
    /**
     * 정책 템플릿 클래스
     */
    private static class PolicyTemplate {
        private Document sourceDocument;
        private String policyType;
        private List<String> conditions = new ArrayList<>();
        private List<String> actions = new ArrayList<>();
        private List<String> resources = new ArrayList<>();
        private List<String> roles = new ArrayList<>();
        private double templateScore;
        private int mergedCount = 1;
        private String createdBy;
        private String createdDate;
        private String complianceFramework;
        private String version;
        
        // Getters and Setters
        public Document getSourceDocument() { return sourceDocument; }
        public void setSourceDocument(Document doc) { this.sourceDocument = doc; }
        
        public String getPolicyType() { return policyType; }
        public void setPolicyType(String type) { this.policyType = type; }
        
        public List<String> getConditions() { return conditions; }
        public void setConditions(List<String> conditions) { this.conditions = conditions; }
        
        public List<String> getActions() { return actions; }
        public void setActions(List<String> actions) { this.actions = actions; }
        
        public List<String> getResources() { return resources; }
        public void setResources(List<String> resources) { this.resources = resources; }
        
        public List<String> getRoles() { return roles; }
        public void setRoles(List<String> roles) { this.roles = roles; }
        
        public double getTemplateScore() { return templateScore; }
        public void setTemplateScore(double score) { this.templateScore = score; }
        
        public int getMergedCount() { return mergedCount; }
        public void setMergedCount(int count) { this.mergedCount = count; }
        
        public String getCreatedBy() { return createdBy; }
        public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
        
        public String getCreatedDate() { return createdDate; }
        public void setCreatedDate(String date) { this.createdDate = date; }
        
        public String getComplianceFramework() { return complianceFramework; }
        public void setComplianceFramework(String framework) { this.complianceFramework = framework; }
        
        public String getVersion() { return version; }
        public void setVersion(String version) { this.version = version; }
    }
}