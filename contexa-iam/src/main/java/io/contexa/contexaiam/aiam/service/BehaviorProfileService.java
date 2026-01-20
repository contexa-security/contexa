package io.contexa.contexaiam.aiam.service;

import io.contexa.contexaiam.aiam.web.BehavioralAnalysisController;
import io.contexa.contexaiam.repository.BehaviorAnomalyEventRepository;
import io.contexa.contexaiam.repository.BehaviorBasedPermissionRepository;
import io.contexa.contexacommon.entity.behavior.BehaviorAnomalyEvent;
import io.contexa.contexacommon.entity.behavior.BehaviorBasedPermission;
import io.contexa.contexacommon.entity.behavior.UserBehaviorProfile;
import io.contexa.contexacommon.repository.UserBehaviorProfileRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class BehaviorProfileService {

    private final UserRepository userRepository;
    private final UserBehaviorProfileRepository behaviorProfileRepository;
    private final BehaviorAnomalyEventRepository anomalyEventRepository;
    private final BehaviorBasedPermissionRepository permissionRepository;

    
    public long getTotalUserCount() {
        return userRepository.count();
    }

    
    public long getActiveUserCount(LocalDateTime date) {
        LocalDateTime startOfDay = date.toLocalDate().atStartOfDay();
        LocalDateTime endOfDay = startOfDay.plusDays(1);
        return anomalyEventRepository.countDistinctUsersByEventTimestampBetween(startOfDay, endOfDay);
    }

    
    public long getAnomalyCount(int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        return anomalyEventRepository.countByEventTimestampAfter(since);
    }

    
    public Map<String, Long> getRiskLevelDistribution(int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        List<BehaviorAnomalyEvent> events = anomalyEventRepository.findByEventTimestampAfter(since);

        return events.stream()
                .collect(Collectors.groupingBy(
                        BehaviorAnomalyEvent::getRiskLevel,
                        Collectors.counting()
                ));
    }

    
    public List<BehavioralAnalysisController.HourlyTrend> getHourlyAnomalyTrend(int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        List<BehaviorAnomalyEvent> events = anomalyEventRepository.findByEventTimestampAfter(since);

        Map<Integer, List<BehaviorAnomalyEvent>> hourlyMap = events.stream()
                .collect(Collectors.groupingBy(e -> e.getEventTimestamp().getHour()));

        List<BehavioralAnalysisController.HourlyTrend> trends = new ArrayList<>();
        for (int hour = 0; hour < 24; hour++) {
            BehavioralAnalysisController.HourlyTrend trend = new BehavioralAnalysisController.HourlyTrend();
            trend.setHour(hour);

            List<BehaviorAnomalyEvent> hourEvents = hourlyMap.getOrDefault(hour, Collections.emptyList());
            trend.setCount(hourEvents.size());

            if (!hourEvents.isEmpty()) {
                double avgScore = hourEvents.stream()
                        .mapToDouble(BehaviorAnomalyEvent::getAnomalyScore)
                        .average()
                        .orElse(0.0);
                trend.setAvgRiskScore(avgScore);
            } else {
                trend.setAvgRiskScore(0.0);
            }

            trends.add(trend);
        }

        return trends;
    }

    
    public List<BehavioralAnalysisController.HighRiskEvent> getRecentHighRiskEvents(int limit) {
        PageRequest pageRequest = PageRequest.of(0, limit, Sort.by(Sort.Direction.DESC, "eventTimestamp"));
        List<BehaviorAnomalyEvent> events = anomalyEventRepository.findByRiskLevelIn(
                Arrays.asList("HIGH", "CRITICAL"),
                pageRequest
        );

        return events.stream().map(event -> {
            BehavioralAnalysisController.HighRiskEvent highRiskEvent = new BehavioralAnalysisController.HighRiskEvent();
            highRiskEvent.setUserId(event.getUserId());
            highRiskEvent.setTimestamp(event.getEventTimestamp());
            highRiskEvent.setActivity(event.getActivity());
            highRiskEvent.setRiskScore(event.getAnomalyScore());
            highRiskEvent.setSummary(event.getAiSummary());
            return highRiskEvent;
        }).collect(Collectors.toList());
    }

    
    public Map<String, Object> getUserProfile(String userId, int days) {
        Map<String, Object> profile = new HashMap<>();

        
        profile.put("userId", userId);
        profile.put("analysisPeriodDays", days);

        
        List<UserBehaviorProfile> profiles = behaviorProfileRepository.findByUserId(userId);
        profile.put("behaviorProfiles", profiles);

        
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        List<BehaviorAnomalyEvent> anomalies = anomalyEventRepository.findByUserIdAndEventTimestampAfter(userId, since);
        profile.put("recentAnomalies", anomalies.size());

        
        double avgRisk = anomalies.stream()
                .mapToDouble(BehaviorAnomalyEvent::getAnomalyScore)
                .average()
                .orElse(0.0);
        profile.put("averageRiskScore", avgRisk);

        
        Map<String, Long> riskDistribution = anomalies.stream()
                .collect(Collectors.groupingBy(BehaviorAnomalyEvent::getRiskLevel, Collectors.counting()));
        profile.put("riskDistribution", riskDistribution);

        return profile;
    }

    
    public List<BehavioralAnalysisController.AnomalyEvent> getUserAnomalies(String userId, int days, int page, int size) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        PageRequest pageRequest = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "eventTimestamp"));

        List<BehaviorAnomalyEvent> events = anomalyEventRepository.findByUserIdAndEventTimestampAfter(
                userId, since, pageRequest
        );

        return events.stream().map(event -> {
            BehavioralAnalysisController.AnomalyEvent anomaly = new BehavioralAnalysisController.AnomalyEvent();
            anomaly.setId(event.getId().toString());
            anomaly.setUserId(event.getUserId());
            anomaly.setTimestamp(event.getEventTimestamp());
            anomaly.setActivity(event.getActivity());
            anomaly.setRiskScore(event.getAnomalyScore());
            anomaly.setRiskLevel(event.getRiskLevel());

            
            if (event.getAnomalyFactors() != null) {
                try {
                    @SuppressWarnings("unchecked")
                    List<String> factors = new com.fasterxml.jackson.databind.ObjectMapper()
                            .readValue(event.getAnomalyFactors(), List.class);
                    anomaly.setAnomalyFactors(factors);
                } catch (Exception e) {
                    anomaly.setAnomalyFactors(Collections.emptyList());
                }
            }

            anomaly.setAiSummary(event.getAiSummary());
            return anomaly;
        }).collect(Collectors.toList());
    }

    
    @Transactional
    public void saveFeedback(String analysisId, boolean isCorrect, String feedback, String adminUser) {
        anomalyEventRepository.findByAiAnalysisId(analysisId).ifPresent(event -> {
            event.setAdminFeedback(isCorrect ? "CORRECT" : "FALSE_POSITIVE");
            event.setFeedbackComment(feedback);
            event.setFeedbackTimestamp(LocalDateTime.now());
            event.setFeedbackBy(adminUser);
            anomalyEventRepository.save(event);

            log.info("피드백 저장 완료: analysisId={}, correct={}, by={}", analysisId, isCorrect, adminUser);
        });
    }

    
    @Transactional
    public void createDynamicPermission(String conditionExpression, String applicableTo,
                                        String permissionAdjustment, String description, String createdBy) {
        BehaviorBasedPermission permission = new BehaviorBasedPermission();
        permission.setConditionExpression(conditionExpression);
        permission.setApplicableTo(applicableTo);
        permission.setPermissionAdjustment(permissionAdjustment);
        permission.setDescription(description);
        permission.setActive(true);
        permission.setPriority(100);
        permission.setCreatedBy(createdBy);
        permission.setCreatedAt(LocalDateTime.now());

        permissionRepository.save(permission);

        log.info("동적 권한 규칙 생성: condition={}, adjustment={}", conditionExpression, permissionAdjustment);
    }

    
    public List<BehaviorBasedPermission> getActivePermissions() {
        return permissionRepository.findByActiveTrue(Sort.by(Sort.Direction.ASC, "priority"));
    }

    
    @Transactional
    public void deactivatePermission(Long permissionId) {
        permissionRepository.findById(permissionId).ifPresent(permission -> {
            permission.setActive(false);
            permissionRepository.save(permission);
            log.info("동적 권한 규칙 비활성화: id={}", permissionId);
        });
    }
}
