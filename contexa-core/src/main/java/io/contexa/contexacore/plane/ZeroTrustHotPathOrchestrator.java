package io.contexa.contexacore.plane;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.hcad.service.HCADSimilarityCalculator;

/**
 * Zero Trust HOT Path Orchestrator Interface
 *
 * <p>
 * HOT Path (유사도 > 0.7)에서도 Zero Trust 원칙을 적용하여
 * 정교한 회피 공격을 탐지하는 기능입니다.
 * </p>
 *
 * <p>
 * Enterprise 모듈에서 구현체를 제공하며, Core 모듈에서는 이 인터페이스를 통해 사용합니다.
 * Spring Boot AutoConfiguration을 통해 Enterprise 구현체가 자동 주입됩니다.
 * </p>
 *
 * @since 0.1.1
 */
public interface ZeroTrustHotPathOrchestrator {

    /**
     * HOT Path 이벤트에 대한 Zero Trust 평가 및 결과 조정
     *
     * @param event SecurityEvent
     * @param originalResult HCAD 분석 원본 결과
     * @return 조정된 TrustedSimilarityResult (Enterprise에서 Zero Trust 평가 후 조정)
     */
    HCADSimilarityCalculator.TrustedSimilarityResult evaluateAndAdjustResult(
            SecurityEvent event,
            HCADSimilarityCalculator.TrustedSimilarityResult originalResult
    );
}
