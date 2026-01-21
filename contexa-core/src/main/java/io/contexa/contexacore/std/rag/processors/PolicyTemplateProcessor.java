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

public class PolicyTemplateProcessor implements DocumentPostProcessor {
    
    @Value("${spring.ai.rag.policy.min-template-score:0.7}")
    private double minTemplateScore;
    
    @Value("${spring.ai.rag.policy.max-templates:10}")
    private int maxTemplates;
    
    @Value("${spring.ai.rag.policy.merge-similar-threshold:0.85}")
    private double mergeSimilarThreshold;

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

        List<PolicyTemplate> templates = extractPolicyTemplates(documents);

        List<PolicyTemplate> mergedTemplates = mergeSimilarTemplates(templates);

        List<PolicyTemplate> rankedTemplates = rankTemplates(mergedTemplates);

        enrichDocumentsWithTemplates(documents, rankedTemplates);

        return sortByTemplateQuality(documents);
    }

    private List<PolicyTemplate> extractPolicyTemplates(List<Document> documents) {
        List<PolicyTemplate> templates = new ArrayList<>();
        
        for (Document doc : documents) {
            String content = doc.getText();
            if (content == null || content.isEmpty()) {
                continue;
            }
            
            PolicyTemplate template = new PolicyTemplate();
            template.setSourceDocument(doc);

            template.setConditions(extractConditions(content));
            template.setActions(extractActions(content));
            template.setResources(extractResources(content));
            template.setRoles(extractRoles(content));

            template.setPolicyType(identifyPolicyType(doc));

            template.setTemplateScore(calculateTemplateScore(template));

            extractTemplateMetadata(template, doc);
            
            if (template.getTemplateScore() >= minTemplateScore) {
                templates.add(template);
            }
        }
        
        return templates;
    }

    private List<String> extractConditions(String content) {
        List<String> conditions = new ArrayList<>();
        Matcher matcher = CONDITION_PATTERN.matcher(content);
        
        while (matcher.find()) {
            String condition = matcher.group(1).trim();
            
            condition = normalizeCondition(condition);
            if (!condition.isEmpty()) {
                conditions.add(condition);
            }
        }
        
        return conditions;
    }

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

    private String identifyPolicyType(Document document) {
        String content = document.getText().toUpperCase();
        Map<String, Object> metadata = document.getMetadata();

        Object policyType = metadata.get("policyType");
        if (policyType != null) {
            return policyType.toString();
        }

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

    private double calculateTemplateScore(PolicyTemplate template) {
        double score = 0.0;

        double structureScore = 0.0;
        if (!template.getConditions().isEmpty()) structureScore += 0.25;
        if (!template.getActions().isEmpty()) structureScore += 0.25;
        if (!template.getResources().isEmpty()) structureScore += 0.25;
        if (!template.getRoles().isEmpty()) structureScore += 0.25;
        score += structureScore * 0.4;

        double clarityScore = calculateClarityScore(template);
        score += clarityScore * 0.3;

        double reusabilityScore = calculateReusabilityScore(template);
        score += reusabilityScore * 0.2;

        double verifiabilityScore = calculateVerifiabilityScore(template);
        score += verifiabilityScore * 0.1;
        
        return Math.min(score, 1.0);
    }

    private double calculateClarityScore(PolicyTemplate template) {
        double score = 0.0;

        for (String condition : template.getConditions()) {
            if (containsSpecificOperators(condition)) {
                score += 0.2;
            }
        }

        for (String action : template.getActions()) {
            if (isSpecificAction(action)) {
                score += 0.2;
            }
        }

        for (String resource : template.getResources()) {
            if (!resource.contains("*") && !resource.contains("?")) {
                score += 0.2;
            }
        }
        
        return Math.min(score, 1.0);
    }

    private double calculateReusabilityScore(PolicyTemplate template) {
        double score = 0.5; 

        int parameterizableElements = 0;
        parameterizableElements += countParameterizableElements(template.getConditions());
        parameterizableElements += countParameterizableElements(template.getActions());
        
        score += Math.min(parameterizableElements * 0.1, 0.3);

        if ("GENERAL_POLICY".equals(template.getPolicyType()) || 
            "ACCESS_CONTROL".equals(template.getPolicyType())) {
            score += 0.2;
        }
        
        return Math.min(score, 1.0);
    }

    private double calculateVerifiabilityScore(PolicyTemplate template) {
        double score = 0.0;

        for (String condition : template.getConditions()) {
            if (containsMeasurableCondition(condition)) {
                score += 0.25;
            }
        }

        for (String action : template.getActions()) {
            if (isAuditableAction(action)) {
                score += 0.25;
            }
        }
        
        return Math.min(score, 1.0);
    }

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

    private double calculateTemplateSimilarity(PolicyTemplate t1, PolicyTemplate t2) {
        double similarity = 0.0;

        if (t1.getPolicyType().equals(t2.getPolicyType())) {
            similarity += 0.3;
        }

        similarity += calculateListSimilarity(t1.getConditions(), t2.getConditions()) * 0.25;

        similarity += calculateListSimilarity(t1.getActions(), t2.getActions()) * 0.25;

        similarity += calculateListSimilarity(t1.getResources(), t2.getResources()) * 0.1;

        similarity += calculateListSimilarity(t1.getRoles(), t2.getRoles()) * 0.1;
        
        return similarity;
    }

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

    private PolicyTemplate mergeTemplates(List<PolicyTemplate> templates) {
        PolicyTemplate merged = new PolicyTemplate();

        PolicyTemplate best = templates.stream()
            .max(Comparator.comparing(PolicyTemplate::getTemplateScore))
            .orElse(templates.get(0));
        
        merged.setPolicyType(best.getPolicyType());
        merged.setSourceDocument(best.getSourceDocument());

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

        merged.setTemplateScore(calculateTemplateScore(merged));
        merged.setMergedCount(templates.size());
        
        return merged;
    }

    private List<PolicyTemplate> rankTemplates(List<PolicyTemplate> templates) {
        return templates.stream()
            .sorted((t1, t2) -> {
                
                int scoreCompare = Double.compare(t2.getTemplateScore(), t1.getTemplateScore());
                if (scoreCompare != 0) return scoreCompare;

                int mergeCompare = Integer.compare(t2.getMergedCount(), t1.getMergedCount());
                if (mergeCompare != 0) return mergeCompare;

                return Integer.compare(
                    t2.getConditions().size() + t2.getActions().size(),
                    t1.getConditions().size() + t1.getActions().size()
                );
            })
            .limit(maxTemplates)
            .collect(Collectors.toList());
    }

    private void enrichDocumentsWithTemplates(List<Document> documents, List<PolicyTemplate> templates) {
        Map<Document, PolicyTemplate> documentTemplateMap = new HashMap<>();

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