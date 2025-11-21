package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * AccessGovernanceLab 연동 커넥터
 *
 * AccessGovernanceLab 분석 결과를 수집하고 과도한 권한 탐지 시 보안 이벤트를 생성합니다.
 *
 * NOTE: AccessGovernanceLab은 aiam 모듈에 위치하므로, aicore에서는 직접 호출할 수 없습니다.
 * 대신 Vector Store에 저장된 권한 분석 결과를 조회하여 이벤트를 생성합니다.
 *
 * 실제 AccessGovernanceLab 실행은 aiam 모듈의 AutonomousPolicySynthesizer에서 수행됩니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class AccessGovernanceLabConnector {

    @Autowired(required = false)
    private UnifiedVectorService unifiedVectorService;

    @Value("${access.governance.enabled:true}")
    private boolean enabled;

    @Value("${access.governance.search.limit:20}")
    private int searchLimit;

    @Value("${access.governance.risk.threshold:0.7}")
    private double riskThreshold;

    /**
     * 과도한 권한 분석 실행
     *
     * @return 발견된 과도한 권한에 대한 보안 이벤트 목록
     */
    public List<SecurityEvent> analyzeExcessivePermissions() {
        List<SecurityEvent> events = new ArrayList<>();

        try {
            // AccessGovernanceLab 실행
            Map<String, Object> analysisResult = runAccessGovernanceAnalysis();

            // 결과 분석
            if (analysisResult != null && !analysisResult.isEmpty()) {
                // 과도한 권한 사용자 탐지
                List<Map<String, Object>> excessiveUsers = extractExcessiveUsers(analysisResult);
                for (Map<String, Object> user : excessiveUsers) {
                    SecurityEvent event = createSecurityEventFromUser(user);
                    if (event != null) {
                        events.add(event);
                    }
                }

                // 미사용 권한 탐지
                List<Map<String, Object>> unusedPermissions = extractUnusedPermissions(analysisResult);
                for (Map<String, Object> permission : unusedPermissions) {
                    SecurityEvent event = createSecurityEventFromPermission(permission);
                    if (event != null) {
                        events.add(event);
                    }
                }

                // 권한 이상 패턴 탐지
                List<Map<String, Object>> anomalies = extractPermissionAnomalies(analysisResult);
                for (Map<String, Object> anomaly : anomalies) {
                    SecurityEvent event = createSecurityEventFromAnomaly(anomaly);
                    if (event != null) {
                        events.add(event);
                    }
                }
            }

            log.info("AccessGovernanceLab 분석 완료: {} 개의 이벤트 생성", events.size());

        } catch (Exception e) {
            log.error("AccessGovernanceLab 분석 실패", e);
        }

        return events;
    }

    /**
     * AccessGovernanceLab 분석 결과 조회 (Vector Store 기반)
     *
     * Vector Store에 저장된 AccessGovernanceLab 분석 결과를 조회합니다.
     * 실제 Lab 실행은 aiam 모듈의 AccessGovernanceLab에서 수행되며,
     * 결과는 AccessVectorService에 의해 Vector Store에 저장됩니다.
     */
    private Map<String, Object> runAccessGovernanceAnalysis() {
        if (!enabled || unifiedVectorService == null) {
            log.warn("[AccessGovernanceConnector] Vector Store가 비활성화되거나 사용 불가");
            return createEmptyResult();
        }

        try {
            log.info("[AccessGovernanceConnector] Vector Store에서 권한 분석 결과 조회");

            // 1. Vector Store에서 최근 권한 분석 결과 검색
            List<Document> analysisResults = searchAccessGovernanceResults();

            // 2. 검색 결과 분석
            if (analysisResults.isEmpty()) {
                log.info("[AccessGovernanceConnector] Vector Store에 권한 분석 결과가 없습니다");
                return createEmptyResult();
            }

            // 3. 결과를 Map으로 변환
            Map<String, Object> result = convertDocumentsToMap(analysisResults);

            log.info("[AccessGovernanceConnector] 분석 결과 조회 완료: {}명 과도권한, {}개 미사용권한, {}개 이상패턴",
                ((List<?>) result.getOrDefault("excessivePermissionUsers", List.of())).size(),
                ((List<?>) result.getOrDefault("unusedPermissions", List.of())).size(),
                ((List<?>) result.getOrDefault("permissionAnomalies", List.of())).size());

            return result;

        } catch (Exception e) {
            log.error("[AccessGovernanceConnector] Vector Store 조회 실패", e);
            return createEmptyResult();
        }
    }

    /**
     * Vector Store에서 권한 거버넌스 분석 결과 검색
     */
    private List<Document> searchAccessGovernanceResults() {
        try {
            // 최근 권한 분석 결과 검색 쿼리
            String query = "권한 거버넌스 분석 과도한 권한 미사용 권한 이상 패턴";

            // documentType=access_governance_analysis 필터링
            // SearchRequest를 사용해야 함
            org.springframework.ai.vectorstore.SearchRequest searchRequest =
                org.springframework.ai.vectorstore.SearchRequest.builder()
                    .query(query)
                    .topK(searchLimit)
                    .filterExpression("documentType == 'access_governance_analysis'")
                    .build();

            // Vector Store 검색
            List<Document> results = unifiedVectorService.searchSimilar(searchRequest);

            log.debug("[AccessGovernanceConnector] Vector Store 검색 결과: {}개 문서", results.size());

            return results;

        } catch (Exception e) {
            log.error("[AccessGovernanceConnector] Vector Store 검색 실패", e);
            return List.of();
        }
    }

    /**
     * Document 목록을 Map으로 변환
     */
    private Map<String, Object> convertDocumentsToMap(List<Document> documents) {
        Map<String, Object> result = new HashMap<>();
        result.put("analysisTime", LocalDateTime.now());

        List<Map<String, Object>> excessiveUsers = new ArrayList<>();
        List<Map<String, Object>> unusedPerms = new ArrayList<>();
        List<Map<String, Object>> anomalies = new ArrayList<>();

        for (Document doc : documents) {
            Map<String, Object> metadata = doc.getMetadata();

            // findingType으로 분류
            String findingType = (String) metadata.get("findingType");
            if (findingType == null) continue;

            double riskScore = extractRiskScore(metadata);

            // 위험 점수 임계값 확인
            if (riskScore < riskThreshold) {
                continue; // 낮은 위험 점수는 무시
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

    /**
     * 메타데이터에서 위험 점수 추출
     */
    private double extractRiskScore(Map<String, Object> metadata) {
        Object riskScore = metadata.get("riskScore");
        if (riskScore instanceof Number) {
            return ((Number) riskScore).doubleValue();
        }

        // severity 기반 점수 계산
        String severity = (String) metadata.get("severity");
        if (severity != null) {
            return calculateRiskScoreFromSeverity(severity);
        }

        return 0.5; // 기본값
    }

    /**
     * Severity 문자열 기반 위험 점수 계산
     */
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

    /**
     * 메타데이터에서 권한 개수 추출
     */
    private int extractPermissionCount(Map<String, Object> metadata) {
        Object count = metadata.get("excessivePermissionCount");
        if (count instanceof Number) {
            return ((Number) count).intValue();
        }

        // Description에서 파싱
        String desc = (String) metadata.get("description");
        if (desc != null && desc.matches(".*\\d+.*")) {
            try {
                String numStr = desc.replaceAll("[^0-9]", "");
                return Integer.parseInt(numStr.substring(0, Math.min(numStr.length(), 3)));
            } catch (Exception e) {
                return 1;
            }
        }

        return 1; // 기본값
    }

    /**
     * 메타데이터에서 미사용 일수 추출
     */
    private int extractUnusedDays(Map<String, Object> metadata) {
        Object days = metadata.get("unusedDays");
        if (days instanceof Number) {
            return ((Number) days).intValue();
        }

        // Description에서 파싱
        String desc = (String) metadata.get("description");
        if (desc != null && desc.contains("일")) {
            try {
                String numStr = desc.replaceAll("[^0-9]", "");
                return Integer.parseInt(numStr.substring(0, Math.min(numStr.length(), 3)));
            } catch (Exception e) {
                return 30;
            }
        }

        return 30; // 기본값
    }

    /**
     * 메타데이터에서 신뢰도 추출
     */
    private double extractConfidence(Map<String, Object> metadata) {
        Object confidence = metadata.get("confidence");
        if (confidence instanceof Number) {
            return ((Number) confidence).doubleValue();
        }

        // severity 기반 신뢰도 계산
        String severity = (String) metadata.get("severity");
        if (severity != null) {
            return calculateConfidenceFromSeverity(severity);
        }

        return 0.5; // 기본값
    }

    /**
     * Severity 문자열 기반 신뢰도 계산
     */
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

    /**
     * 빈 결과 생성
     */
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

    /**
     * 과도한 권한 사용자 추출
     */
    private List<Map<String, Object>> extractExcessiveUsers(Map<String, Object> analysisResult) {
        List<Map<String, Object>> users = new ArrayList<>();

        // 실제 구현에서는 분석 결과에서 과도한 권한 사용자 정보 추출
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> excessiveUsers =
            (List<Map<String, Object>>) analysisResult.get("excessivePermissionUsers");

        if (excessiveUsers != null) {
            return excessiveUsers;
        }

        return users;
    }

    /**
     * 미사용 권한 추출
     */
    private List<Map<String, Object>> extractUnusedPermissions(Map<String, Object> analysisResult) {
        List<Map<String, Object>> permissions = new ArrayList<>();

        // 실제 구현에서는 분석 결과에서 미사용 권한 정보 추출
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> unusedPerms =
            (List<Map<String, Object>>) analysisResult.get("unusedPermissions");

        if (unusedPerms != null) {
            return unusedPerms;
        }

        return permissions;
    }

    /**
     * 권한 이상 패턴 추출
     */
    private List<Map<String, Object>> extractPermissionAnomalies(Map<String, Object> analysisResult) {
        List<Map<String, Object>> anomalies = new ArrayList<>();

        // 실제 구현에서는 분석 결과에서 이상 패턴 정보 추출
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> detectedAnomalies =
            (List<Map<String, Object>>) analysisResult.get("permissionAnomalies");

        if (detectedAnomalies != null) {
            return detectedAnomalies;
        }

        return anomalies;
    }

    /**
     * 사용자 정보로부터 보안 이벤트 생성
     */
    private SecurityEvent createSecurityEventFromUser(Map<String, Object> user) {
        try {
            String userId = (String) user.get("userId");
            String userName = (String) user.get("userName");
            Integer excessiveCount = (Integer) user.get("excessivePermissionCount");
            Double riskScore = (Double) user.get("riskScore");

            return SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventType(SecurityEvent.EventType.ACCESS_VIOLATION)
                .severity(calculateSeverity(riskScore))
                .description(String.format("사용자 '%s'에게 과도한 권한 %d개 탐지", userName, excessiveCount))
                .timestamp(LocalDateTime.now())
                .userId(userId)
                .metadata(user)
                .build();

        } catch (Exception e) {
            log.warn("사용자 정보에서 보안 이벤트 생성 실패: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 권한 정보로부터 보안 이벤트 생성
     */
    private SecurityEvent createSecurityEventFromPermission(Map<String, Object> permission) {
        try {
            String permissionId = (String) permission.get("permissionId");
            String permissionName = (String) permission.get("permissionName");
            Integer unusedDays = (Integer) permission.get("unusedDays");

            return SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventType(SecurityEvent.EventType.ANOMALY_DETECTED)
                .severity(SecurityEvent.Severity.LOW)
                .description(String.format("권한 '%s'가 %d일 동안 미사용", permissionName, unusedDays))
                .timestamp(LocalDateTime.now())
                .targetResource(permissionId)
                .metadata(permission)
                .build();

        } catch (Exception e) {
            log.warn("권한 정보에서 보안 이벤트 생성 실패: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 이상 패턴으로부터 보안 이벤트 생성
     */
    private SecurityEvent createSecurityEventFromAnomaly(Map<String, Object> anomaly) {
        try {
            String anomalyType = (String) anomaly.get("type");
            String description = (String) anomaly.get("description");
            Double confidence = (Double) anomaly.get("confidence");

            return SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventType(SecurityEvent.EventType.ANOMALY_DETECTED)
                .severity(calculateSeverity(confidence))
                .description(description)
                .timestamp(LocalDateTime.now())
                .metadata(anomaly)
                .build();

        } catch (Exception e) {
            log.warn("이상 패턴에서 보안 이벤트 생성 실패: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 위험 점수에 따른 심각도 계산
     */
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

    /**
     * 정기적인 권한 분석 실행 여부 확인
     */
    public boolean shouldRunAnalysis() {
        // 실제 구현에서는 마지막 실행 시간 확인 등의 로직 추가
        return true;
    }
}