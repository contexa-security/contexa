package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.client.SimulationClient;
import io.contexa.contexacore.simulation.domain.UserBehaviorPattern;
import io.contexa.contexacore.simulation.strategy.IBehaviorAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.*;
import java.util.concurrent.*;

/**
 * Behavioral Anomaly Attack 전략
 *
 * 정상적인 사용자 행동 패턴을 학습하여 비정상적인 활동을 수행하면서도 탐지를 회피
 */
@Slf4j
@Component
public class BehavioralAnomalyStrategy implements IBehaviorAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Autowired(required = false)
    private SimulationClient simulationClient;

    @Value("${simulation.attack.behavioral-anomaly.max-actions:100}")
    private int maxActions;

    @Value("${simulation.attack.behavioral-anomaly.delay-ms:2000}")
    private int delayMs;

    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.BEHAVIORAL_ANOMALY;
    }

    @Override
    public int getPriority() {
        return 85;
    }

    @Override
    public AttackCategory getCategory() {
        return AttackCategory.BEHAVIORAL;
    }

    @Override
    public boolean validateContext(AttackContext context) {
        return context != null && context.getTargetUser() != null;
    }

    @Override
    public long getEstimatedDuration() {
        return maxActions * delayMs + 10000;
    }

    @Override
    public String getDescription() {
        return "Behavioral Anomaly Attack - Performs abnormal user behavior patterns to evade detection";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.LOW;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully perform abnormal activities without triggering behavioral detection";
    }

    // IBehaviorAttack interface methods
    @Override
    public BehaviorResult mimicBehavior(UserBehaviorPattern pattern) {
        BehaviorResult result = new BehaviorResult();
        result.setAnomalyDetected(false);
        result.setAnomalyType("MIMIC");
        result.setAnomalyScore(0.3);
        return result;
    }

    @Override
    public BehaviorResult performImpossibleTravel(String userId, List<Location> locations, List<Integer> timeIntervals) {
        BehaviorResult result = new BehaviorResult();
        result.setAnomalyDetected(true);
        result.setAnomalyType("IMPOSSIBLE_TRAVEL");
        result.setAnomalyScore(0.9);
        return result;
    }

    @Override
    public BehaviorResult performAbnormalTimeAccess(String userId, LocalDateTime accessTime) {
        BehaviorResult result = new BehaviorResult();
        result.setAnomalyDetected(true);
        result.setAnomalyType("ABNORMAL_TIME");
        result.setAnomalyScore(0.7);
        return result;
    }

    @Override
    public BehaviorResult violateDeviceTrust(String userId, String deviceFingerprint) {
        BehaviorResult result = new BehaviorResult();
        result.setAnomalyDetected(true);
        result.setAnomalyType("DEVICE_TRUST_VIOLATION");
        result.setZeroTrustViolation(true);
        result.setAnomalyScore(0.8);
        return result;
    }

    @Override
    public BehaviorResult performMassDataAccess(String userId, long dataVolume, int duration) {
        BehaviorResult result = new BehaviorResult();
        result.setAnomalyDetected(true);
        result.setAnomalyType("MASS_DATA_ACCESS");
        result.setAnomalyScore(0.85);
        return result;
    }

    @Override
    public BehaviorResult generateAnomalousNetworkPattern(String userId, NetworkPattern networkPattern) {
        BehaviorResult result = new BehaviorResult();
        result.setAnomalyDetected(true);
        result.setAnomalyType("NETWORK_ANOMALY");
        result.setAnomalyScore(0.75);
        return result;
    }

    @Override
    public BehaviorResult simulateAccountTakeover(UserBehaviorPattern legitimatePattern, UserBehaviorPattern attackerPattern) {
        BehaviorResult result = new BehaviorResult();
        result.setAnomalyDetected(true);
        result.setAnomalyType("ACCOUNT_TAKEOVER");
        result.setAnomalyScore(0.95);
        result.setZeroTrustViolation(true);
        return result;
    }

    @Override
    public BehaviorResult generateInsiderThreat(String userId, List<ThreatIndicator> threatIndicators) {
        BehaviorResult result = new BehaviorResult();
        result.setAnomalyDetected(true);
        result.setAnomalyType("INSIDER_THREAT");
        result.setAnomalyScore(0.9);
        Map<String, Object> evidences = new HashMap<>();
        evidences.put("threatIndicators", threatIndicators);
        result.setEvidences(evidences);
        return result;
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== Behavioral Anomaly Attack 시작: target={} ===", context.getTargetUser());

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.BEHAVIORAL_ANOMALY)
            .attackName("Behavioral Anomaly Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("behavior")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 정상 행동 패턴 학습
            int learningDays = Integer.parseInt(
                context.getParameters().getOrDefault("learningDays", "7").toString()
            );
            UserBehaviorProfile normalProfile = learnUserBehavior(context.getTargetUser(), learningDays);
            attackLog.add("Learned normal behavior profile for " + learningDays + " days");
            attackLog.add("Normal activity hours: " + normalProfile.activeHours);
            attackLog.add("Average actions per day: " + normalProfile.avgActionsPerDay);

            // 2. 이상 행동 유형 결정
            String anomalyType = context.getParameters().getOrDefault("anomalyType", "DATA_EXFIL").toString();
            String stealthLevel = context.getParameters().getOrDefault("stealthLevel", "HIGH").toString();
            attackLog.add("Anomaly type: " + anomalyType);
            attackLog.add("Stealth level: " + stealthLevel);

            // 3. 은닉 수준에 따른 행동 계획 수립
            List<AnomalousAction> plannedActions = planAnomalousActions(
                normalProfile, anomalyType, stealthLevel
            );
            attackLog.add("Planned " + plannedActions.size() + " anomalous actions");

            // 4. 이상 행동 실행
            int successfulActions = 0;
            int detectedActions = 0;

            for (AnomalousAction action : plannedActions) {
                // 정상 시간대 확인
                if (shouldExecuteNow(normalProfile, action, stealthLevel)) {
                    boolean actionResult = executeAnomalousAction(action, context, attackLog);

                    if (actionResult) {
                        successfulActions++;
                        attackLog.add("[SUCCESS] " + action.type + " completed");

                        // 탐지 여부 확인
                        if (wasDetected(action, stealthLevel)) {
                            detectedActions++;
                            attackLog.add("[DETECTED] Anomaly detected by security system");
                        }
                    } else {
                        attackLog.add("[FAILED] " + action.type + " blocked");
                    }

                    // 스텔스 수준에 따른 지연
                    Thread.sleep(calculateDelay(stealthLevel, normalProfile));
                } else {
                    attackLog.add("[WAITING] Delaying action to match normal behavior");
                }
            }

            // 5. 결과 평가
            double successRate = (double) successfulActions / plannedActions.size();
            double detectionRate = (double) detectedActions / successfulActions;

            if (successRate > 0.5) {
                result.setSuccessful(true);
                result.setRiskScore(Math.min(1.0, 0.4 + (successRate * 0.4) + (1 - detectionRate) * 0.2));
                attackLog.add("Anomalous behavior executed successfully with " +
                            (100 - detectionRate * 100) + "% evasion rate");
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.3);
                attackLog.add("Anomalous behavior failed - security controls effective");
            }

            result.setDetected(detectionRate > 0.3);
            result.setBlocked(successRate < 0.3);

            result.setDetails(Map.of(
                "attackLog", attackLog,
                "anomalyType", anomalyType,
                "stealthLevel", stealthLevel,
                "successfulActions", successfulActions,
                "detectedActions", detectedActions,
                "totalActions", plannedActions.size(),
                "successRate", String.format("%.2f%%", successRate * 100),
                "detectionRate", String.format("%.2f%%", detectionRate * 100)
            ));

        } catch (Exception e) {
            log.error("Behavioral anomaly attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);

        // 이벤트 발행 - 행동 기반 공격은 인가 결정 이벤트로 처리
        if (eventPublisher != null) {
            String resource = "behavior_analysis:" + context.getTargetUser();
            String action = "BEHAVIORAL_ANOMALY_" + result.getDetails().getOrDefault("anomalyType", "UNKNOWN");
            eventPublisher.publishAuthorizationDecision(
                result,
                context.getTargetUser(),
                resource,
                action,
                result.isSuccessful(),
                result.isSuccessful() ?
                    "Behavioral anomaly attack succeeded - evasion rate: " + result.getDetails().getOrDefault("detectionRate", "unknown") :
                    "Behavioral anomaly attack blocked by security controls"
            );
        }

        log.info("Behavioral Anomaly Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        return result;
    }

    private UserBehaviorProfile learnUserBehavior(String user, int days) {
        UserBehaviorProfile profile = new UserBehaviorProfile();

        // 시뮬레이션: 사용자별 정상 행동 패턴
        if (user.contains("admin")) {
            profile.activeHours = Arrays.asList(9, 10, 11, 14, 15, 16, 17);
            profile.avgActionsPerDay = 150;
            profile.commonActions = Arrays.asList("login", "view_dashboard", "manage_users", "review_logs");
            profile.accessPatterns = Map.of(
                "database", 20,
                "config", 10,
                "logs", 30,
                "users", 15
            );
        } else {
            profile.activeHours = Arrays.asList(9, 10, 11, 12, 14, 15, 16, 17, 18);
            profile.avgActionsPerDay = 80;
            profile.commonActions = Arrays.asList("login", "view_data", "download_report", "logout");
            profile.accessPatterns = Map.of(
                "reports", 40,
                "dashboard", 30,
                "profile", 10,
                "documents", 20
            );
        }

        profile.avgSessionDuration = 45; // minutes
        profile.avgDataTransfer = 1024 * 50; // 50KB average
        profile.loginLocations = Arrays.asList("Office", "Home");
        profile.deviceFingerprints = generateDeviceFingerprints(2);

        return profile;
    }

    private List<AnomalousAction> planAnomalousActions(
            UserBehaviorProfile profile, String anomalyType, String stealthLevel) {

        List<AnomalousAction> actions = new ArrayList<>();

        switch (anomalyType) {
            case "DATA_EXFIL":
                actions.addAll(planDataExfiltration(profile, stealthLevel));
                break;
            case "PRIVILEGE_ESCALATION":
                actions.addAll(planPrivilegeEscalation(profile, stealthLevel));
                break;
            case "LATERAL_MOVEMENT":
                actions.addAll(planLateralMovement(profile, stealthLevel));
                break;
            case "RESOURCE_ABUSE":
                actions.addAll(planResourceAbuse(profile, stealthLevel));
                break;
        }

        // 스텔스 수준에 따라 정상 행동 섞기
        if ("HIGH".equals(stealthLevel) || "ADAPTIVE".equals(stealthLevel)) {
            actions.addAll(generateNormalActions(profile, actions.size() / 2));
        }

        Collections.shuffle(actions); // 행동 순서 무작위화
        return actions.subList(0, Math.min(actions.size(), maxActions));
    }

    private List<AnomalousAction> planDataExfiltration(UserBehaviorProfile profile, String stealthLevel) {
        List<AnomalousAction> actions = new ArrayList<>();

        // 데이터 유출 시나리오
        if ("LOW".equals(stealthLevel)) {
            // 대량 다운로드
            actions.add(new AnomalousAction("BULK_DOWNLOAD", "Download all customer records", 95));
            actions.add(new AnomalousAction("DATABASE_DUMP", "Export entire database", 98));
        } else if ("MEDIUM".equals(stealthLevel)) {
            // 점진적 다운로드
            for (int i = 0; i < 10; i++) {
                actions.add(new AnomalousAction("GRADUAL_DOWNLOAD",
                    "Download batch " + i + " (1000 records)", 60));
            }
        } else {
            // 은밀한 유출
            for (int i = 0; i < 20; i++) {
                actions.add(new AnomalousAction("STEALTH_EXFIL",
                    "Normal query with extra data (" + i + ")", 30));
                // 정상 행동 추가
                if (i % 3 == 0) {
                    actions.add(new AnomalousAction("NORMAL_QUERY",
                        "Regular database query", 5));
                }
            }
        }

        return actions;
    }

    private List<AnomalousAction> planPrivilegeEscalation(UserBehaviorProfile profile, String stealthLevel) {
        List<AnomalousAction> actions = new ArrayList<>();

        actions.add(new AnomalousAction("ENUM_PERMISSIONS", "Enumerate current permissions", 40));
        actions.add(new AnomalousAction("FIND_VULNS", "Scan for privilege escalation vectors", 70));

        if ("LOW".equals(stealthLevel)) {
            actions.add(new AnomalousAction("EXPLOIT_VULN", "Direct privilege escalation attempt", 90));
        } else {
            actions.add(new AnomalousAction("GRADUAL_PRIV", "Request additional permissions", 50));
            actions.add(new AnomalousAction("IMPERSONATE", "Attempt user impersonation", 60));
        }

        actions.add(new AnomalousAction("ACCESS_ADMIN", "Access administrative functions", 80));

        return actions;
    }

    private List<AnomalousAction> planLateralMovement(UserBehaviorProfile profile, String stealthLevel) {
        List<AnomalousAction> actions = new ArrayList<>();

        actions.add(new AnomalousAction("NETWORK_SCAN", "Scan internal network", 60));
        actions.add(new AnomalousAction("SERVICE_ENUM", "Enumerate available services", 50));

        String[] targets = {"HR_System", "Finance_DB", "Dev_Server", "Backup_Storage"};
        for (String target : targets) {
            if ("HIGH".equals(stealthLevel)) {
                // 은밀한 접근
                actions.add(new AnomalousAction("STEALTH_ACCESS",
                    "Indirect access to " + target, 40));
            } else {
                // 직접 접근
                actions.add(new AnomalousAction("DIRECT_ACCESS",
                    "Direct connection to " + target, 70));
            }
        }

        return actions;
    }

    private List<AnomalousAction> planResourceAbuse(UserBehaviorProfile profile, String stealthLevel) {
        List<AnomalousAction> actions = new ArrayList<>();

        if ("LOW".equals(stealthLevel)) {
            actions.add(new AnomalousAction("CRYPTOMINING", "Start cryptocurrency mining", 95));
            actions.add(new AnomalousAction("DDOS_BOTNET", "Join botnet for DDoS", 90));
        } else {
            // 점진적 자원 사용 증가
            for (int i = 1; i <= 10; i++) {
                int intensity = i * 10;
                actions.add(new AnomalousAction("GRADUAL_LOAD",
                    "Increase resource usage to " + intensity + "%", intensity / 2));
            }
        }

        return actions;
    }

    private List<AnomalousAction> generateNormalActions(UserBehaviorProfile profile, int count) {
        List<AnomalousAction> normalActions = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            String action = profile.commonActions.get(
                ThreadLocalRandom.current().nextInt(profile.commonActions.size())
            );
            normalActions.add(new AnomalousAction("NORMAL", action, 5));
        }

        return normalActions;
    }

    private boolean shouldExecuteNow(UserBehaviorProfile profile, AnomalousAction action, String stealthLevel) {
        if ("LOW".equals(stealthLevel)) {
            return true; // 시간 고려 없이 실행
        }

        int currentHour = LocalTime.now().getHour();

        if ("HIGH".equals(stealthLevel) || "ADAPTIVE".equals(stealthLevel)) {
            // 정상 업무 시간에만 실행
            return profile.activeHours.contains(currentHour);
        }

        // MEDIUM - 업무 시간 근처에서 실행
        return currentHour >= 7 && currentHour <= 20;
    }

    private boolean executeAnomalousAction(AnomalousAction action, AttackContext context,
                                          List<String> attackLog) {

        if (simulationClient != null) {
            try {
                Map<String, Object> params = new HashMap<>();
                params.put("action", action.type);
                params.put("description", action.description);
                params.put("user", context.getTargetUser());

                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/api/behavior/anomaly",
                    params
                );

                return response.getStatusCode().is2xxSuccessful();

            } catch (Exception e) {
                attackLog.add("Action failed: " + e.getMessage());
                return false;
            }
        }

        // 실제 공격 성공 여부는 공격 복잡도와 시스템 응답으로 판단
        // detectionScore가 높을수록 탐지되기 쉬운 공격
        // 낮은 점수일수록 은밀하고 성공 가능성이 높음
        return action.detectionScore < 50 ||
               (action.detectionScore < 70 && System.currentTimeMillis() % 100 < 30);
    }

    private boolean wasDetected(AnomalousAction action, String stealthLevel) {
        double detectionChance = action.detectionScore / 100.0;

        // 스텔스 수준에 따른 탐지율 조정
        switch (stealthLevel) {
            case "HIGH":
                detectionChance *= 0.3;
                break;
            case "ADAPTIVE":
                detectionChance *= 0.5;
                break;
            case "MEDIUM":
                detectionChance *= 0.7;
                break;
            case "LOW":
            default:
                // 기본 탐지율 유지
                break;
        }

        // 실제 탐지 여부는 공격 복잡도, 스텔스 레벨, 시스템 상태로 결정
        long seed = System.currentTimeMillis() % 1000;
        double threshold = detectionChance * 1000;
        return seed < threshold;
    }

    private int calculateDelay(String stealthLevel, UserBehaviorProfile profile) {
        switch (stealthLevel) {
            case "HIGH":
                return delayMs * 3 + ThreadLocalRandom.current().nextInt(delayMs * 2);
            case "ADAPTIVE":
                return delayMs * 2 + ThreadLocalRandom.current().nextInt(delayMs);
            case "MEDIUM":
                return delayMs + ThreadLocalRandom.current().nextInt(delayMs / 2);
            case "LOW":
            default:
                return 100; // 최소 지연
        }
    }

    private List<String> generateDeviceFingerprints(int count) {
        List<String> fingerprints = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            fingerprints.add(UUID.randomUUID().toString());
        }
        return fingerprints;
    }

    private static class UserBehaviorProfile {
        List<Integer> activeHours;
        int avgActionsPerDay;
        List<String> commonActions;
        Map<String, Integer> accessPatterns;
        int avgSessionDuration;
        int avgDataTransfer;
        List<String> loginLocations;
        List<String> deviceFingerprints;
    }

    private static class AnomalousAction {
        String type;
        String description;
        int detectionScore; // 0-100, 높을수록 탐지 가능성 높음

        AnomalousAction(String type, String description, int detectionScore) {
            this.type = type;
            this.description = description;
            this.detectionScore = detectionScore;
        }
    }
}