package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacoreenterprise.properties.AccessGovernanceProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class AccessGovernanceLabConnector {

    private final AccessGovernanceProperties accessGovernanceProperties;

    @Autowired(required = false)
    private UnifiedVectorService unifiedVectorService;

    public List<SecurityEvent> analyzeExcessivePermissions() {
        List<SecurityEvent> events = new ArrayList<>();

        try {
            
            Map<String, Object> analysisResult = runAccessGovernanceAnalysis();

            if (analysisResult != null && !analysisResult.isEmpty()) {
                
                List<Map<String, Object>> excessiveUsers = extractExcessiveUsers(analysisResult);
                for (Map<String, Object> user : excessiveUsers) {
                    SecurityEvent event = createSecurityEventFromUser(user);
                    if (event != null) {
                        events.add(event);
                    }
                }

                List<Map<String, Object>> unusedPermissions = extractUnusedPermissions(analysisResult);
                for (Map<String, Object> permission : unusedPermissions) {
                    SecurityEvent event = createSecurityEventFromPermission(permission);
                    if (event != null) {
                        events.add(event);
                    }
                }

                List<Map<String, Object>> anomalies = extractPermissionAnomalies(analysisResult);
                for (Map<String, Object> anomaly : anomalies) {
                    SecurityEvent event = createSecurityEventFromAnomaly(anomaly);
                    if (event != null) {
                        events.add(event);
                    }
                }
            }

        } catch (Exception e) {
            log.error("AccessGovernanceLab 분석 실패", e);
        }

        return events;
    }

    private Map<String, Object> runAccessGovernanceAnalysis() {
        if (!accessGovernanceProperties.isEnabled() || unifiedVectorService == null) {
            log.warn("[AccessGovernanceConnector] Vector Store가 비활성화되거나 사용 불가");
            return createEmptyResult();
        }

        try {

            List<Document> analysisResults = searchAccessGovernanceResults();

            if (analysisResults.isEmpty()) {
                                return createEmptyResult();
            }

            Map<String, Object> result = convertDocumentsToMap(analysisResults);

            return result;

        } catch (Exception e) {
            log.error("[AccessGovernanceConnector] Vector Store 조회 실패", e);
            return createEmptyResult();
        }
    }

    private List<Document> searchAccessGovernanceResults() {
        try {
            
            String query = "권한 거버넌스 분석 과도한 권한 미사용 권한 이상 패턴";

            org.springframework.ai.vectorstore.SearchRequest searchRequest =
                org.springframework.ai.vectorstore.SearchRequest.builder()
                    .query(query)
                    .topK(accessGovernanceProperties.getSearch().getLimit())
                    .filterExpression("documentType == 'access_governance_analysis'")
                    .build();

            List<Document> results = unifiedVectorService.searchSimilar(searchRequest);

            return results;

        } catch (Exception e) {
            log.error("[AccessGovernanceConnector] Vector Store 검색 실패", e);
            return List.of();
        }
    }

    private Map<String, Object> convertDocumentsToMap(List<Document> documents) {
        Map<String, Object> result = new HashMap<>();
        result.put("analysisTime", LocalDateTime.now());

        List<Map<String, Object>> excessiveUsers = new ArrayList<>();
        List<Map<String, Object>> unusedPerms = new ArrayList<>();
        List<Map<String, Object>> anomalies = new ArrayList<>();

        for (Document doc : documents) {
            Map<String, Object> metadata = doc.getMetadata();

            String findingType = (String) metadata.get("findingType");
            if (findingType == null) continue;

            double riskScore = extractRiskScore(metadata);

            if (riskScore < accessGovernanceProperties.getRisk().getThreshold()) {
                continue; 
            }

            switch (findingType.toUpperCase()) {
                case "EXCESSIVE_PRIVILEGE":
                    Map<String, Object> userMap = new HashMap<>();
                    userMap.put("userId", metadata.get("affectedEntity"));
                    userMap.put("userName", metadata.get("affectedEntity"));
                    userMap.put("description", metadata.get("description"));
                    userMap.put("riskScore", riskScore);
                    userMap.put("excessivePermissionCount", extractPermissionCount(metadata));
                    excessiveUsers.add(userMap);
                    break;

                case "UNUSED_PERMISSION":
                    Map<String, Object> permMap = new HashMap<>();
                    permMap.put("permissionId", metadata.get("affectedEntity"));
                    permMap.put("permissionName", metadata.get("description"));
                    permMap.put("unusedDays", extractUnusedDays(metadata));
                    unusedPerms.add(permMap);
                    break;

                case "ANOMALOUS_PATTERN":
                case "POLICY_VIOLATION":
                case "SEGREGATION_VIOLATION":
                    Map<String, Object> anomalyMap = new HashMap<>();
                    anomalyMap.put("type", findingType);
                    anomalyMap.put("description", metadata.get("description"));
                    anomalyMap.put("confidence", extractConfidence(metadata));
                    anomalies.add(anomalyMap);
                    break;
            }
        }

        result.put("excessivePermissionUsers", excessiveUsers);
        result.put("unusedPermissions", unusedPerms);
        result.put("permissionAnomalies", anomalies);
        result.put("usersAnalyzed", excessiveUsers.size());
        result.put("permissionsAnalyzed", unusedPerms.size());

        return result;
    }

    private double extractRiskScore(Map<String, Object> metadata) {
        Object riskScore = metadata.get("riskScore");
        if (riskScore instanceof Number) {
            return ((Number) riskScore).doubleValue();
        }

        String severity = (String) metadata.get("severity");
        if (severity != null) {
            return calculateRiskScoreFromSeverity(severity);
        }

        return 0.5; 
    }

    private double calculateRiskScoreFromSeverity(String severity) {
        switch (severity.toUpperCase()) {
            case "CRITICAL":
                return 0.95;
            case "HIGH":
                return 0.8;
            case "MEDIUM":
                return 0.6;
            case "LOW":
                return 0.3;
            default:
                return 0.1;
        }
    }

    private int extractPermissionCount(Map<String, Object> metadata) {
        Object count = metadata.get("excessivePermissionCount");
        if (count instanceof Number) {
            return ((Number) count).intValue();
        }

        String desc = (String) metadata.get("description");
        if (desc != null && desc.matches(".*\\d+.*")) {
            try {
                String numStr = desc.replaceAll("[^0-9]", "");
                return Integer.parseInt(numStr.substring(0, Math.min(numStr.length(), 3)));
            } catch (Exception e) {
                return 1;
            }
        }

        return 1; 
    }

    private int extractUnusedDays(Map<String, Object> metadata) {
        Object days = metadata.get("unusedDays");
        if (days instanceof Number) {
            return ((Number) days).intValue();
        }

        String desc = (String) metadata.get("description");
        if (desc != null && desc.contains("일")) {
            try {
                String numStr = desc.replaceAll("[^0-9]", "");
                return Integer.parseInt(numStr.substring(0, Math.min(numStr.length(), 3)));
            } catch (Exception e) {
                return 30;
            }
        }

        return 30; 
    }

    private double extractConfidence(Map<String, Object> metadata) {
        Object confidence = metadata.get("confidence");
        if (confidence instanceof Number) {
            return ((Number) confidence).doubleValue();
        }

        String severity = (String) metadata.get("severity");
        if (severity != null) {
            return calculateConfidenceFromSeverity(severity);
        }

        return 0.5; 
    }

    private double calculateConfidenceFromSeverity(String severity) {
        switch (severity.toUpperCase()) {
            case "CRITICAL":
                return 0.95;
            case "HIGH":
                return 0.85;
            case "MEDIUM":
                return 0.75;
            case "LOW":
                return 0.6;
            default:
                return 0.5;
        }
    }

    private Map<String, Object> createEmptyResult() {
        Map<String, Object> result = new HashMap<>();
        result.put("analysisTime", LocalDateTime.now());
        result.put("usersAnalyzed", 0);
        result.put("permissionsAnalyzed", 0);
        result.put("excessivePermissionUsers", new ArrayList<>());
        result.put("unusedPermissions", new ArrayList<>());
        result.put("permissionAnomalies", new ArrayList<>());
        return result;
    }

    private List<Map<String, Object>> extractExcessiveUsers(Map<String, Object> analysisResult) {
        List<Map<String, Object>> users = new ArrayList<>();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> excessiveUsers =
            (List<Map<String, Object>>) analysisResult.get("excessivePermissionUsers");

        if (excessiveUsers != null) {
            return excessiveUsers;
        }

        return users;
    }

    private List<Map<String, Object>> extractUnusedPermissions(Map<String, Object> analysisResult) {
        List<Map<String, Object>> permissions = new ArrayList<>();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> unusedPerms =
            (List<Map<String, Object>>) analysisResult.get("unusedPermissions");

        if (unusedPerms != null) {
            return unusedPerms;
        }

        return permissions;
    }

    private List<Map<String, Object>> extractPermissionAnomalies(Map<String, Object> analysisResult) {
        List<Map<String, Object>> anomalies = new ArrayList<>();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> detectedAnomalies =
            (List<Map<String, Object>>) analysisResult.get("permissionAnomalies");

        if (detectedAnomalies != null) {
            return detectedAnomalies;
        }

        return anomalies;
    }

    private SecurityEvent createSecurityEventFromUser(Map<String, Object> user) {
        try {
            String userId = (String) user.get("userId");
            String userName = (String) user.get("userName");
            Integer excessiveCount = (Integer) user.get("excessivePermissionCount");
            Double riskScore = (Double) user.get("riskScore");

            Map<String, Object> enrichedMetadata = new HashMap<>(user);
            enrichedMetadata.put("incidentType", "ACCESS_VIOLATION");
            return SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .source(SecurityEvent.EventSource.IAM)
                .severity(calculateSeverity(riskScore))
                .description(String.format("사용자 '%s'에게 과도한 권한 %d개 탐지", userName, excessiveCount))
                .timestamp(LocalDateTime.now())
                .userId(userId)
                .metadata(enrichedMetadata)
                .build();

        } catch (Exception e) {
            log.warn("사용자 정보에서 보안 이벤트 생성 실패: {}", e.getMessage());
            return null;
        }
    }

    private SecurityEvent createSecurityEventFromPermission(Map<String, Object> permission) {
        try {
            String permissionId = (String) permission.get("permissionId");
            String permissionName = (String) permission.get("permissionName");
            Integer unusedDays = (Integer) permission.get("unusedDays");

            Map<String, Object> enrichedMetadata = new HashMap<>(permission);
            enrichedMetadata.put("incidentType", "ANOMALY_DETECTED");
            enrichedMetadata.put("targetResource", permissionId);
            return SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .source(SecurityEvent.EventSource.IAM)
                .severity(SecurityEvent.Severity.LOW)
                .description(String.format("권한 '%s'가 %d일 동안 미사용", permissionName, unusedDays))
                .timestamp(LocalDateTime.now())
                .metadata(enrichedMetadata)
                .build();

        } catch (Exception e) {
            log.warn("권한 정보에서 보안 이벤트 생성 실패: {}", e.getMessage());
            return null;
        }
    }

    private SecurityEvent createSecurityEventFromAnomaly(Map<String, Object> anomaly) {
        try {
            String anomalyType = (String) anomaly.get("type");
            String description = (String) anomaly.get("description");
            Double confidence = (Double) anomaly.get("confidence");

            Map<String, Object> enrichedMetadata = new HashMap<>(anomaly);
            enrichedMetadata.put("incidentType", "ANOMALY_DETECTED");
            return SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .source(SecurityEvent.EventSource.IAM)
                .severity(calculateSeverity(confidence))
                .description(description)
                .timestamp(LocalDateTime.now())
                .metadata(enrichedMetadata)
                .build();

        } catch (Exception e) {
            log.warn("이상 패턴에서 보안 이벤트 생성 실패: {}", e.getMessage());
            return null;
        }
    }

    private SecurityEvent.Severity calculateSeverity(Double score) {
        if (score == null) {
            return SecurityEvent.Severity.LOW;
        }

        if (score >= 0.8) {
            return SecurityEvent.Severity.CRITICAL;
        } else if (score >= 0.6) {
            return SecurityEvent.Severity.HIGH;
        } else if (score >= 0.4) {
            return SecurityEvent.Severity.MEDIUM;
        } else {
            return SecurityEvent.Severity.LOW;
        }
    }

    public boolean shouldRunAnalysis() {
        
        return true;
    }
}