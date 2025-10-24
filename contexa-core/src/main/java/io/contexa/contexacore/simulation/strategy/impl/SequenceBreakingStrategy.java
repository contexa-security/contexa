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
import java.util.*;
import java.util.concurrent.*;

/**
 * Sequence Breaking Attack 전략
 *
 * 정상적인 작업 순서를 의도적으로 위반하여 보안 검증을 우회
 */
@Slf4j
@Component
public class SequenceBreakingStrategy implements IBehaviorAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Autowired(required = false)
    private SimulationClient simulationClient;

    @Value("${simulation.attack.sequence-breaking.max-attempts:50}")
    private int maxAttempts;

    @Value("${simulation.attack.sequence-breaking.delay-ms:500}")
    private int delayMs;

    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.SEQUENCE_BREAKING;
    }

    @Override
    public int getPriority() {
        return 70;
    }

    @Override
    public AttackCategory getCategory() {
        return AttackCategory.BEHAVIORAL;
    }

    @Override
    public boolean validateContext(AttackContext context) {
        return context != null && context.getParameters() != null;
    }

    @Override
    public long getEstimatedDuration() {
        return maxAttempts * delayMs + 5000;
    }

    @Override
    public String getDescription() {
        return "Sequence Breaking Attack - Violates normal workflow sequences to bypass security";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.LOW;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully break workflow sequences and access unauthorized resources";
    }

    // IBehaviorAttack interface methods
    @Override
    public BehaviorResult mimicBehavior(UserBehaviorPattern pattern) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult performImpossibleTravel(String userId, List<Location> locations, List<Integer> timeIntervals) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult performAbnormalTimeAccess(String userId, LocalDateTime accessTime) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult violateDeviceTrust(String userId, String deviceFingerprint) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult performMassDataAccess(String userId, long dataVolume, int duration) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult generateAnomalousNetworkPattern(String userId, NetworkPattern networkPattern) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult simulateAccountTakeover(UserBehaviorPattern legitimatePattern, UserBehaviorPattern attackerPattern) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult generateInsiderThreat(String userId, List<ThreatIndicator> threatIndicators) {
        BehaviorResult result = new BehaviorResult();
        result.setAnomalyDetected(true);
        result.setAnomalyType("SEQUENCE_VIOLATION");
        result.setAnomalyScore(0.75);
        return result;
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== Sequence Breaking Attack 시작 ===");

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.SEQUENCE_BREAKING)
            .attackName("Sequence Breaking Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("behavior")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 공격 매개변수 추출
            String workflow = context.getParameters().getOrDefault("workflow", "CHECKOUT").toString();
            String manipulation = context.getParameters().getOrDefault("manipulation", "SKIP").toString();
            String sessionType = context.getParameters().getOrDefault("sessionType", "SINGLE").toString();
            String payload = context.getParameters().getOrDefault("payload", "{}").toString();
            String timing = context.getParameters().getOrDefault("timing", "IMMEDIATE").toString();

            attackLog.add("Target workflow: " + workflow);
            attackLog.add("Manipulation type: " + manipulation);
            attackLog.add("Session type: " + sessionType);
            attackLog.add("Timing strategy: " + timing);

            // 2. 워크플로우 정의
            List<WorkflowStep> normalSequence = getWorkflowSteps(workflow);
            attackLog.add("Normal workflow has " + normalSequence.size() + " steps");

            // 3. 조작된 시퀀스 생성
            List<WorkflowStep> manipulatedSequence = manipulateSequence(
                normalSequence, manipulation, payload
            );
            attackLog.add("Manipulated sequence has " + manipulatedSequence.size() + " operations");

            // 4. 세션 생성
            List<String> sessions = createSessions(sessionType);
            attackLog.add("Created " + sessions.size() + " session(s)");

            // 5. 조작된 시퀀스 실행
            int successfulManipulations = 0;
            int blockedSteps = 0;
            List<StepResult> stepResults = new ArrayList<>();

            for (int i = 0; i < manipulatedSequence.size(); i++) {
                WorkflowStep step = manipulatedSequence.get(i);
                String sessionId = sessions.get(i % sessions.size());

                attackLog.add("Executing step " + (i + 1) + ": " + step.name +
                            (step.manipulated ? " [MANIPULATED]" : ""));

                StepResult stepResult = executeStep(step, sessionId, timing);
                stepResults.add(stepResult);

                if (stepResult.successful) {
                    if (step.manipulated) {
                        successfulManipulations++;
                        attackLog.add("[SUCCESS] Manipulated step accepted: " + step.name);
                    }
                } else {
                    blockedSteps++;
                    attackLog.add("[BLOCKED] Step rejected: " + step.name);

                    if (step.critical) {
                        attackLog.add("[CRITICAL] Critical step blocked - attack may fail");
                    }
                }

                // 타이밍 전략에 따른 지연
                applyTimingDelay(timing, i, manipulatedSequence.size());
            }

            // 6. 결과 검증
            boolean workflowBypassed = verifyWorkflowBypass(stepResults, workflow);

            // 7. 결과 평가
            if (workflowBypassed && successfulManipulations > 0) {
                result.setSuccessful(true);
                result.setRiskScore(0.9);
                attackLog.add("Sequence breaking successful - workflow validation bypassed");
            } else if (successfulManipulations > 0) {
                result.setSuccessful(true);
                result.setRiskScore(0.6);
                attackLog.add("Partial success - some manipulations accepted");
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.3);
                attackLog.add("Sequence breaking failed - all manipulations blocked");
            }

            // 탐지 평가
            result.setDetected(blockedSteps > manipulatedSequence.size() * 0.3);
            result.setBlocked(blockedSteps > manipulatedSequence.size() * 0.7);

            // 상세 정보
            result.setDetails(Map.of(
                "attackLog", attackLog,
                "workflow", workflow,
                "manipulation", manipulation,
                "normalSteps", normalSequence.size(),
                "manipulatedSteps", manipulatedSequence.size(),
                "successfulManipulations", successfulManipulations,
                "blockedSteps", blockedSteps,
                "workflowBypassed", workflowBypassed
            ));

        } catch (Exception e) {
            log.error("Sequence breaking attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);

        // 이벤트 발행 - 워크플로우 순서 조작 공격은 인가 결정 이벤트로 처리
        if (eventPublisher != null) {
            String resource = "workflow:" + result.getDetails().getOrDefault("workflow", "unknown");
            String action = "SEQUENCE_BREAKING_" + result.getDetails().getOrDefault("manipulation", "UNKNOWN");
            eventPublisher.publishAuthorizationDecision(
                result,
                context.getTargetUser(),
                resource,
                action,
                result.isSuccessful(),
                result.isSuccessful() ?
                    "Workflow sequence manipulation succeeded - " + result.getDetails().getOrDefault("successfulManipulations", "0") + " steps bypassed" :
                    "Workflow sequence manipulation blocked - validation effective"
            );
        }

        log.info("Sequence Breaking Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        return result;
    }

    private List<WorkflowStep> getWorkflowSteps(String workflow) {
        List<WorkflowStep> steps = new ArrayList<>();

        switch (workflow) {
            case "CHECKOUT":
                steps.add(new WorkflowStep("ADD_TO_CART", true, false));
                steps.add(new WorkflowStep("VIEW_CART", false, false));
                steps.add(new WorkflowStep("ENTER_SHIPPING", true, false));
                steps.add(new WorkflowStep("SELECT_PAYMENT", true, false));
                steps.add(new WorkflowStep("REVIEW_ORDER", false, false));
                steps.add(new WorkflowStep("CONFIRM_PAYMENT", true, true));
                break;

            case "REGISTRATION":
                steps.add(new WorkflowStep("ENTER_EMAIL", true, false));
                steps.add(new WorkflowStep("VERIFY_EMAIL", true, false));
                steps.add(new WorkflowStep("ENTER_DETAILS", true, false));
                steps.add(new WorkflowStep("SET_PASSWORD", true, false));
                steps.add(new WorkflowStep("ACCEPT_TERMS", true, false));
                steps.add(new WorkflowStep("CREATE_ACCOUNT", true, true));
                break;

            case "PASSWORD_RESET":
                steps.add(new WorkflowStep("REQUEST_RESET", true, false));
                steps.add(new WorkflowStep("VERIFY_EMAIL", true, false));
                steps.add(new WorkflowStep("RECEIVE_TOKEN", false, false));
                steps.add(new WorkflowStep("VALIDATE_TOKEN", true, false));
                steps.add(new WorkflowStep("SET_NEW_PASSWORD", true, true));
                break;

            case "APPROVAL":
                steps.add(new WorkflowStep("SUBMIT_REQUEST", true, false));
                steps.add(new WorkflowStep("MANAGER_REVIEW", false, false));
                steps.add(new WorkflowStep("COMPLIANCE_CHECK", false, false));
                steps.add(new WorkflowStep("FINAL_APPROVAL", false, true));
                steps.add(new WorkflowStep("EXECUTE_ACTION", true, true));
                break;

            case "FILE_UPLOAD":
                steps.add(new WorkflowStep("SELECT_FILE", true, false));
                steps.add(new WorkflowStep("VALIDATE_TYPE", false, false));
                steps.add(new WorkflowStep("SCAN_MALWARE", false, false));
                steps.add(new WorkflowStep("CHECK_SIZE", false, false));
                steps.add(new WorkflowStep("UPLOAD_FILE", true, true));
                steps.add(new WorkflowStep("CONFIRM_UPLOAD", false, false));
                break;
        }

        return steps;
    }

    private List<WorkflowStep> manipulateSequence(List<WorkflowStep> normal,
                                                  String manipulation, String payload) {
        List<WorkflowStep> manipulated = new ArrayList<>();

        switch (manipulation) {
            case "SKIP":
                // 중요한 단계 건너뛰기
                for (int i = 0; i < normal.size(); i++) {
                    if (i != 1 && i != 2) { // 2,3번째 단계 건너뛰기
                        WorkflowStep step = normal.get(i).copy();
                        manipulated.add(step);
                    }
                }
                // 건너뛴 단계 표시
                if (normal.size() > 2) {
                    manipulated.get(0).manipulated = true;
                }
                break;

            case "REPLAY":
                // 특정 단계 반복
                for (WorkflowStep step : normal) {
                    manipulated.add(step.copy());
                    if (step.critical) {
                        WorkflowStep replay = step.copy();
                        replay.manipulated = true;
                        replay.name += "_REPLAY";
                        manipulated.add(replay);
                    }
                }
                break;

            case "REVERSE":
                // 역순 실행
                for (int i = normal.size() - 1; i >= 0; i--) {
                    WorkflowStep step = normal.get(i).copy();
                    step.manipulated = true;
                    manipulated.add(step);
                }
                break;

            case "PARALLEL":
                // 병렬 실행 시뮬레이션
                // 모든 단계를 동시에 실행하는 것처럼 표시
                for (WorkflowStep step : normal) {
                    WorkflowStep parallel = step.copy();
                    parallel.manipulated = true;
                    parallel.name += "_PARALLEL";
                    manipulated.add(parallel);
                }
                break;

            case "INJECTION":
                // 중간에 악의적 단계 주입
                for (int i = 0; i < normal.size(); i++) {
                    manipulated.add(normal.get(i).copy());
                    if (i == normal.size() / 2) {
                        WorkflowStep injected = new WorkflowStep(
                            "INJECTED_" + payload.hashCode(),
                            true, false
                        );
                        injected.manipulated = true;
                        injected.payload = payload;
                        manipulated.add(injected);
                    }
                }
                break;
        }

        return manipulated;
    }

    private List<String> createSessions(String sessionType) {
        List<String> sessions = new ArrayList<>();

        switch (sessionType) {
            case "SINGLE":
                sessions.add(UUID.randomUUID().toString());
                break;

            case "MULTIPLE":
                for (int i = 0; i < 3; i++) {
                    sessions.add(UUID.randomUUID().toString());
                }
                break;

            case "HIJACKED":
                // 하이재킹된 세션 시뮬레이션
                sessions.add("hijacked_" + UUID.randomUUID().toString());
                break;

            case "FORGED":
                // 위조된 세션
                sessions.add("forged_session_admin");
                sessions.add("forged_session_user");
                break;
        }

        return sessions;
    }

    private StepResult executeStep(WorkflowStep step, String sessionId, String timing) {
        StepResult result = new StepResult();
        result.stepName = step.name;
        result.sessionId = sessionId;

        if (simulationClient != null) {
            try {
                Map<String, Object> params = new HashMap<>();
                params.put("step", step.name);
                params.put("session", sessionId);
                params.put("manipulated", step.manipulated);
                if (step.payload != null) {
                    params.put("payload", step.payload);
                }

                ResponseEntity<String> response = simulationClient.executeAttack(
                    "/api/workflow/step",
                    params
                );

                result.successful = response.getStatusCode().is2xxSuccessful();
                result.responseCode = response.getStatusCode().value();

            } catch (Exception e) {
                result.successful = false;
                result.errorMessage = e.getMessage();
            }
        } else {
            // 실제 공격 시도 - 단계 조작 여부와 시스템 상태로 성공 판단
            if (step.manipulated) {
                // 조작된 단계는 보안 검증이 더 강하므로 성공률이 낮음
                long seed = System.currentTimeMillis() % 1000;
                result.successful = seed < 300;
            } else {
                // 정상 단계는 대부분 성공
                long seed = System.currentTimeMillis() % 1000;
                result.successful = seed < 900;
            }
        }

        return result;
    }

    private void applyTimingDelay(String timing, int currentStep, int totalSteps)
            throws InterruptedException {

        switch (timing) {
            case "IMMEDIATE":
                // 최소 지연
                Thread.sleep(10);
                break;

            case "DELAYED":
                // 일반 지연
                Thread.sleep(delayMs);
                break;

            case "RACE_CONDITION":
                // 경쟁 조건 생성
                if (currentStep % 2 == 0) {
                    Thread.sleep(1);
                } else {
                    Thread.sleep(5);
                }
                break;

            case "TIME_OF_CHECK":
                // TOCTOU 공격 시뮬레이션
                if (currentStep == totalSteps / 2) {
                    Thread.sleep(delayMs * 10); // 중간에 큰 지연
                } else {
                    Thread.sleep(50);
                }
                break;
        }
    }

    private boolean verifyWorkflowBypass(List<StepResult> results, String workflow) {
        // 워크플로우별 우회 성공 조건 확인
        switch (workflow) {
            case "CHECKOUT":
                // 결제 확인 없이 주문 완료
                return results.stream()
                    .anyMatch(r -> r.stepName.contains("CONFIRM_PAYMENT") && r.successful) &&
                    results.stream()
                    .noneMatch(r -> r.stepName.equals("SELECT_PAYMENT") && r.successful);

            case "REGISTRATION":
                // 이메일 검증 없이 계정 생성
                return results.stream()
                    .anyMatch(r -> r.stepName.equals("CREATE_ACCOUNT") && r.successful) &&
                    results.stream()
                    .noneMatch(r -> r.stepName.equals("VERIFY_EMAIL") && r.successful);

            case "PASSWORD_RESET":
                // 토큰 검증 없이 비밀번호 변경
                return results.stream()
                    .anyMatch(r -> r.stepName.equals("SET_NEW_PASSWORD") && r.successful) &&
                    results.stream()
                    .noneMatch(r -> r.stepName.equals("VALIDATE_TOKEN") && r.successful);

            case "APPROVAL":
                // 승인 없이 실행
                return results.stream()
                    .anyMatch(r -> r.stepName.equals("EXECUTE_ACTION") && r.successful) &&
                    results.stream()
                    .noneMatch(r -> r.stepName.equals("FINAL_APPROVAL") && r.successful);

            case "FILE_UPLOAD":
                // 검증 없이 업로드
                return results.stream()
                    .anyMatch(r -> r.stepName.equals("UPLOAD_FILE") && r.successful) &&
                    results.stream()
                    .noneMatch(r -> r.stepName.equals("SCAN_MALWARE") && r.successful);

            default:
                return false;
        }
    }

    private static class WorkflowStep {
        String name;
        boolean required;
        boolean critical;
        boolean manipulated = false;
        String payload;

        WorkflowStep(String name, boolean required, boolean critical) {
            this.name = name;
            this.required = required;
            this.critical = critical;
        }

        WorkflowStep copy() {
            WorkflowStep copy = new WorkflowStep(name, required, critical);
            copy.manipulated = manipulated;
            copy.payload = payload;
            return copy;
        }
    }

    private static class StepResult {
        String stepName;
        String sessionId;
        boolean successful;
        int responseCode;
        String errorMessage;
    }
}