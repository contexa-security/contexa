package io.contexa.contexacore.simulation.listener;

import io.contexa.contexacore.domain.entity.SimulationResult;
import io.contexa.contexacore.simulation.event.SimulationProcessingCompleteEvent;
import io.contexa.contexacore.repository.SimulationResultRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * 시뮬레이션 결과 이벤트 리스너
 *
 * SecurityPlaneAgent에서 발행된 시뮬레이션 처리 완료 이벤트를 수신하여
 * 데이터베이스에 저장합니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SimulationResultListener {

    private final SimulationResultRepository simulationResultRepository;

    /**
     * 시뮬레이션 처리 완료 이벤트 핸들러
     *
     * 비동기로 처리되어 메인 플로우에 영향을 주지 않습니다.
     *
     * @param event 시뮬레이션 처리 완료 이벤트
     */
    @EventListener
    @Async("simulationExecutor")
    @Transactional
    public void handleSimulationComplete(SimulationProcessingCompleteEvent event) {
        log.info("Simulation processing complete event received - eventId: {}, attackId: {}, mode: {}",
                event.getEventId(), event.getAttackId(), event.getSimulationMode());

        try {
            // 이미 저장된 결과가 있는지 확인 (중복 방지)
            if (simulationResultRepository.existsByEventId(event.getEventId())) {
                log.warn("Simulation result already exists for eventId: {}", event.getEventId());
                return;
            }

            // SimulationResult 엔티티 생성
            SimulationResult result = buildSimulationResult(event);

            // 데이터베이스 저장
            SimulationResult saved = simulationResultRepository.save(result);

            log.info("Simulation result saved successfully - eventId: {}, attackId: {}, " +
                    "detected: {}, blocked: {}, mode: {}, processingTime: {}ms",
                    saved.getEventId(),
                    saved.getAttackId(),
                    saved.isDetected(),
                    saved.isBlocked(),
                    saved.getSimulationMode(),
                    saved.getProcessingTimeMs());

            // 통계 로그 출력
            logStatistics(saved);

        } catch (Exception e) {
            log.error("Failed to save simulation result for eventId: {}", event.getEventId(), e);
            // 실패한 경우에도 기본 정보는 저장 시도
            saveFailedResult(event, e);
        }
    }

    /**
     * SimulationResult 엔티티 빌드
     *
     * @param event 처리 완료 이벤트
     * @return SimulationResult 엔티티
     */
    private SimulationResult buildSimulationResult(SimulationProcessingCompleteEvent event) {
        SimulationResult.SimulationResultBuilder builder = SimulationResult.builder()
                .eventId(event.getEventId())
                .attackId(event.getAttackId())
                .attackType(event.getAttackType())
                .targetUser(event.getTargetUser())
                .sourceIp(event.getSourceIp())
                .detected(event.isDetected())
                .blocked(event.isBlocked())
                .riskScore(event.getRiskScore())
                .confidenceScore(event.getConfidenceScore())
                .simulationMode(event.getSimulationMode())
                .processingTimeMs(event.getProcessingTimeMs())
                .aiAnalysisTimeMs(event.getAiAnalysisTimeMs())
                .processedAt(event.getProcessedAt() != null ? event.getProcessedAt() : LocalDateTime.now())
                .processingSuccess(true);

        // ProcessingMode가 있으면 문자열로 저장
        if (event.getProcessingMode() != null) {
            builder.processingMode(event.getProcessingMode().toString());
        }

        // ResponseActions 저장
        if (event.getResponseActions() != null && !event.getResponseActions().isEmpty()) {
            builder.responseActions(event.getResponseActions());
        }

        // ProcessingResult에서 추가 정보 추출
        Map<String, Object> metadata = new HashMap<>();
        if (event.getMetadata() != null) {
            metadata.putAll(event.getMetadata());
        }

        if (event.getProcessingResult() != null) {
            metadata.put("processingPath", event.getProcessingResult().getProcessingPath());
            metadata.put("executedActions", event.getProcessingResult().getExecutedActions());
            metadata.put("incidentCreated", event.getProcessingResult().isRequiresIncident());

            // ProcessingResult에서 metadata를 통해 campaignId와 sessionId 추출
            if (event.getProcessingResult().getMetadata() != null) {
                Object campaignId = event.getProcessingResult().getMetadata().get("campaignId");
                if (campaignId != null) {
                    builder.campaignId(campaignId.toString());
                }

                Object sessionId = event.getProcessingResult().getMetadata().get("sessionId");
                if (sessionId != null) {
                    builder.sessionId(sessionId.toString());
                }
            }
        }

        if (!metadata.isEmpty()) {
            builder.metadata(metadata);
        }

        return builder.build();
    }

    /**
     * 실패한 결과 저장
     *
     * 처리 중 오류가 발생해도 기본 정보는 저장합니다.
     *
     * @param event 처리 완료 이벤트
     * @param error 발생한 오류
     */
    private void saveFailedResult(SimulationProcessingCompleteEvent event, Exception error) {
        try {
            SimulationResult failedResult = SimulationResult.builder()
                    .eventId(event.getEventId())
                    .attackId(event.getAttackId() != null ? event.getAttackId() : "unknown")
                    .attackType(event.getAttackType() != null ? event.getAttackType() : "unknown")
                    .targetUser(event.getTargetUser())
                    .sourceIp(event.getSourceIp())
                    .detected(false)
                    .blocked(false)
                    .riskScore(0.0)
                    .confidenceScore(0.0)
                    .simulationMode(event.getSimulationMode() != null ?
                            event.getSimulationMode() :
                            SimulationProcessingCompleteEvent.SimulationMode.PROTECTED)
                    .processingTimeMs(event.getProcessingTimeMs())
                    .processedAt(LocalDateTime.now())
                    .processingSuccess(false)
                    .errorMessage(error.getMessage() != null ?
                            error.getMessage().substring(0, Math.min(error.getMessage().length(), 500)) :
                            "Unknown error")
                    .build();

            simulationResultRepository.save(failedResult);
            log.info("Failed simulation result saved for eventId: {}", event.getEventId());

        } catch (Exception e) {
            log.error("Failed to save error record for eventId: {}", event.getEventId(), e);
        }
    }

    /**
     * 통계 로그 출력
     *
     * @param result 저장된 시뮬레이션 결과
     */
    private void logStatistics(SimulationResult result) {
        try {
            // 해당 공격 타입의 탐지율과 차단율 조회
            double detectionRate = simulationResultRepository.getDetectionRateByAttackType(
                    result.getAttackType(), result.getSimulationMode());
            double blockingRate = simulationResultRepository.getBlockingRateByAttackType(
                    result.getAttackType(), result.getSimulationMode());
            double avgProcessingTime = simulationResultRepository.getAverageProcessingTime(
                    result.getAttackType(), result.getSimulationMode());

            log.info("Statistics for {} in {} mode - Detection rate: {:.2f}%, Blocking rate: {:.2f}%, " +
                    "Avg processing time: {:.2f}ms",
                    result.getAttackType(),
                    result.getSimulationMode(),
                    detectionRate * 100,
                    blockingRate * 100,
                    avgProcessingTime);

        } catch (Exception e) {
            log.debug("Failed to log statistics: {}", e.getMessage());
        }
    }
}