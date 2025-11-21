package io.contexa.contexacore.simulation.service;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.context.SimulationModeHolder;
import io.contexa.contexacore.simulation.factory.AttackStrategyFactory;
import io.contexa.contexacore.simulation.generator.AttackScenarioGenerator;
import io.contexa.contexacore.repository.AttackResultRepository;
import io.contexa.contexacore.simulation.strategy.IAttackStrategy;
import io.contexa.contexacore.simulation.strategy.IAttackStrategy.AttackContext;
import io.contexa.contexacore.simulation.tracker.DataBreachTracker;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

/**
 * 이중 모드 시뮬레이션 서비스
 *
 * 무방비 모드와 방어 모드에서 동일한 공격 시나리오를 실행하여
 * AI 보안 시스템의 효과성을 측정합니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class DualModeSimulationService {

    private final AttackStrategyFactory strategyFactory;
    private final AttackScenarioGenerator scenarioGenerator;
    private final AttackResultRepository attackResultRepository;
    private final DataBreachTracker dataBreachTracker;

    /**
     * 이중 모드 시뮬레이션 실행
     *
     * @param campaignId 캠페인 ID
     * @return 공격 결과 목록
     */
    @Transactional
    public List<AttackResult> runSimulation(String campaignId) {
        log.info("Starting dual-mode simulation for campaign: {}", campaignId);

        List<AttackResult> allResults = new ArrayList<>();

        // 공격 유형 정의 (팩토리에서 사용하는 키)
        String[] attackTypes = {
            "VELOCITY_ATTACK",
            "BRUTE_FORCE",
            "IDOR",
            "SESSION_HIJACKING"
        };

        // 각 공격 유형에 대해 두 모드로 실행
        for (String attackType : attackTypes) {
            log.info("\n--- Testing Attack Type: {} ---", attackType);

            // 1. 무방비 모드 실행
            log.info("Executing in UNPROTECTED mode...");
            AttackResult unprotectedResult = executeAttack(
                campaignId,
                attackType,
                SimulationModeHolder.Mode.UNPROTECTED
            );
            allResults.add(unprotectedResult);

            // 약간의 지연 추가 (시스템 안정화)
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // 2. 방어 모드 실행
            log.info("Executing in PROTECTED mode...");
            AttackResult protectedResult = executeAttack(
                campaignId,
                attackType,
                SimulationModeHolder.Mode.PROTECTED
            );
            allResults.add(protectedResult);

            // 결과 비교 로깅
            logComparisonResults(attackType, unprotectedResult, protectedResult);
        }

        // 전체 결과 저장
        attackResultRepository.saveAll(allResults);

        // 최종 요약
        printSimulationSummary(campaignId, allResults);

        return allResults;
    }

    /**
     * 단일 공격 실행
     */
    private AttackResult executeAttack(
            String campaignId,
            String attackType,
            SimulationModeHolder.Mode mode) {

        String attackId = UUID.randomUUID().toString();

        // 시뮬레이션 컨텍스트 설정
        SimulationModeHolder.setMode(mode, campaignId, attackId);

        try {
            // 공격 전략 가져오기
            IAttackStrategy strategy = strategyFactory.getStrategy(attackType);

            // 공격 컨텍스트 생성
            AttackContext context = new AttackContext();
            context.setAttackId(attackId);
            context.setTargetUser("customer-" + (int)(Math.random() * 1000 + 1));  // 랜덤 고객 선택
            context.setTargetEndpoint("/api/customers/");
            context.setParameters(new HashMap<>());

            // 모드 정보 추가
            context.setParameter("simulationMode", mode.name());
            context.setParameter("campaignId", campaignId);
            context.setParameter("attackType", attackType);

            // 공격 실행
            AttackResult result = strategy.execute(context);

            // 결과에 모드 정보 추가
            result.getDetails().put("simulationMode", mode.name());
            result.setCampaignId(campaignId);

            // 데이터 유출 추적 (무방비 모드에서만)
            if (mode == SimulationModeHolder.Mode.UNPROTECTED && result.isDataBreached()) {
                int breachedRecords = (int) result.getDetails().getOrDefault("breachedRecords", 0);
                dataBreachTracker.recordBreach(
                    campaignId,
                    attackId,
                    breachedRecords,
                    mode.name()
                );
            }

            log.info("Attack {} in {} mode - Success: {}, Data Breached: {}",
                attackType, mode, result.isAttackSuccessful(), result.isDataBreached());

            return result;

        } finally {
            // 컨텍스트 정리
            SimulationModeHolder.clear();
        }
    }

    /**
     * 공격 결과 비교 로깅
     */
    private void logComparisonResults(
            String attackType,
            AttackResult unprotected,
            AttackResult protected_) {

        log.info("\n[{}] Result Comparison:", attackType);
        log.info("  Unprotected - Success: {}, Breach: {}",
            unprotected.isAttackSuccessful(), unprotected.isDataBreached());
        log.info("  Protected   - Success: {}, Breach: {}",
            protected_.isAttackSuccessful(), protected_.isDataBreached());

        // 개선도 계산
        if (unprotected.isAttackSuccessful() && !protected_.isAttackSuccessful()) {
            log.info("  AI Security successfully blocked the attack!");
        } else if (!unprotected.isAttackSuccessful() && !protected_.isAttackSuccessful()) {
            log.info("  Attack failed in both modes");
        } else if (unprotected.isAttackSuccessful() && protected_.isAttackSuccessful()) {
            log.warn("  Attack succeeded in both modes - needs investigation");
        }
    }

    /**
     * 시뮬레이션 요약 출력
     */
    private void printSimulationSummary(String campaignId, List<AttackResult> results) {
        log.info("\n========== SIMULATION SUMMARY ==========");
        log.info("Campaign ID: {}", campaignId);

        // 모드별 분석
        long unprotectedSuccess = results.stream()
            .filter(r -> "UNPROTECTED".equals(r.getDetails().get("simulationMode")))
            .filter(AttackResult::isAttackSuccessful)
            .count();

        long protectedSuccess = results.stream()
            .filter(r -> "PROTECTED".equals(r.getDetails().get("simulationMode")))
            .filter(AttackResult::isAttackSuccessful)
            .count();

        long unprotectedBreach = results.stream()
            .filter(r -> "UNPROTECTED".equals(r.getDetails().get("simulationMode")))
            .filter(AttackResult::isDataBreached)
            .count();

        long protectedBreach = results.stream()
            .filter(r -> "PROTECTED".equals(r.getDetails().get("simulationMode")))
            .filter(AttackResult::isDataBreached)
            .count();

        log.info("\nUnprotected Mode:");
        log.info("  - Successful Attacks: {}/{}", unprotectedSuccess, results.size()/2);
        log.info("  - Data Breaches: {}", unprotectedBreach);

        log.info("\nProtected Mode:");
        log.info("  - Successful Attacks: {}/{}", protectedSuccess, results.size()/2);
        log.info("  - Data Breaches: {}", protectedBreach);

        // 효과성 계산
        double preventionRate = 0;
        if (unprotectedSuccess > 0) {
            preventionRate = ((double)(unprotectedSuccess - protectedSuccess) / unprotectedSuccess) * 100;
        }

        log.info("\nSecurity Effectiveness:");
        log.info("  - Attack Prevention Rate: {:.2f}%", preventionRate);
        log.info("  - Data Protection: {} breaches prevented", unprotectedBreach - protectedBreach);
        log.info("=========================================\n");
    }
}