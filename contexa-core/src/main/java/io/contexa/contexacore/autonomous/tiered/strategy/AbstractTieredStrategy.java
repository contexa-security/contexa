package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacore.autonomous.config.FeedbackConstants;
import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import io.contexa.contexacore.autonomous.tiered.feedback.LayerFeedbackService;
import io.contexa.contexacore.hcad.service.HCADVectorIntegrationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Tiered Strategy 추상 기반 클래스
 *
 * Layer1/Layer2/Layer3 전략의 공통 기능을 제공합니다:
 * - Cold→Hot Path 동기화
 * - Hot Path 피드백
 * - 공통 유틸리티 메서드
 *
 * 주의사항:
 * - 기존 Layer 클래스의 모든 기능 유지
 * - 공통 기능만 추출하여 제공
 * - 각 Layer의 독립성 보장
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
public abstract class AbstractTieredStrategy implements ThreatEvaluationStrategy {

    @Autowired(required = false)
    protected HCADVectorIntegrationService hcadVectorService;

    @Autowired(required = false)
    protected LayerFeedbackService layerFeedbackService;

    @Autowired(required = false)
    protected FeedbackIntegrationProperties feedbackProperties;

    /**
     * Hot Path 피드백 공통 로직
     *
     * riskScore가 임계값 이상일 경우 Cold→Hot 동기화를 수행합니다.
     * 각 Layer는 이 메서드를 호출하여 동기화를 수행할 수 있습니다.
     *
     * @param event 보안 이벤트
     * @param decision 보안 결정
     */
    protected void feedbackToHotPath(SecurityEvent event, SecurityDecision decision) {
        if (hcadVectorService == null || feedbackProperties == null) {
            return;
        }

        try {
            double riskScore = decision.getRiskScore();
            double indexingThreshold = getIndexingThreshold();

            // riskScore >= threshold인 경우 동기화 수행
            if (riskScore >= indexingThreshold) {
                log.info("[{}] High-risk pattern detected - riskScore: {}, initiating Cold→Hot sync",
                    getLayerName(), String.format("%.2f", riskScore));

                // Hot Path 동기화 실행
                syncFeedbackToHotPath(event, decision);
            }

        } catch (Exception e) {
            log.warn("[{}] Failed to feedback to hot path", getLayerName(), e);
        }
    }

    /**
     * Cold→Hot Path 동기화 공통 로직
     *
     * Layer별 피드백을 Redis에 인덱싱하고 임베딩을 업데이트하여
     * Hot Path의 실시간 탐지 정확도를 향상시킵니다.
     *
     * @param event 보안 이벤트
     * @param decision 보안 결정
     */
    protected void syncFeedbackToHotPath(SecurityEvent event, SecurityDecision decision) {
        if (hcadVectorService == null) {
            return;
        }

        try {
            String userId = getUserId(event);
            String layerName = getLayerName();

            // Layer별 피드백 인덱싱
            if ("Layer1".equals(layerName)) {
                layerFeedbackService.indexLayer1Feedback(event, decision);
                log.info("[Layer1] 피드백 인덱싱 완료 - userId: {}, riskScore: {}",
                    userId, String.format("%.2f", decision.getRiskScore()));
            } else if ("Layer2".equals(layerName)) {
                layerFeedbackService.indexLayer2Feedback(event, decision);
                log.info("[Layer2] 피드백 인덱싱 완료 - userId: {}, riskScore: {}",
                    userId, String.format("%.2f", decision.getRiskScore()));
            } else if ("Layer3".equals(layerName)) {
                layerFeedbackService.indexLayer3Feedback(event, decision);
                log.info("[Layer3] 피드백 인덱싱 완료 - userId: {}, riskScore: {}",
                    userId, String.format("%.2f", decision.getRiskScore()));
            }

            // Cold→Hot 동기화 (Redis 임베딩 업데이트)
            hcadVectorService.syncColdPathToHotPath(userId)
                .thenAccept(v -> log.info("[{}] Cold→Hot sync completed - userId: {}",
                    layerName, userId))
                .exceptionally(ex -> {
                    log.warn("[{}] Cold→Hot sync failed - userId: {}",
                        layerName, userId, ex);
                    return null;
                });

        } catch (Exception e) {
            log.warn("[{}] Failed to sync feedback to hot path", getLayerName(), e);
        }
    }

    /**
     * 사용자 ID 추출 공통 로직
     *
     * event에서 userId를 추출하며, 없을 경우 기본값을 반환합니다.
     *
     * @param event 보안 이벤트
     * @return 사용자 ID (기본값: DEFAULT_USER_ID)
     */
    protected String getUserId(SecurityEvent event) {
        return event.getUserId() != null ?
            event.getUserId() : FeedbackConstants.DEFAULT_USER_ID;
    }

    /**
     * Indexing Threshold 반환
     *
     * 각 Layer는 이 메서드를 오버라이드하여 고유한 threshold를 설정할 수 있습니다.
     * 기본값: FeedbackIntegrationProperties.getRiskScore().getIndexingThreshold()
     *
     * @return indexing threshold (기본값: 7.0)
     */
    protected double getIndexingThreshold() {
        if (feedbackProperties != null) {
            return feedbackProperties.getRiskScore().getIndexingThreshold();
        }
        return 7.0; // 기본값
    }

    /**
     * Layer 이름 반환 (로깅용)
     *
     * 각 Layer 구현체는 이 메서드를 구현하여 고유한 Layer 이름을 반환해야 합니다.
     *
     * @return Layer 이름 (예: "Layer1", "Layer2", "Layer3")
     */
    protected abstract String getLayerName();
}