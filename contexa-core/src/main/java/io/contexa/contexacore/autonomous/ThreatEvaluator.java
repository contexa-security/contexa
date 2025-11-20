package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;

/**
 * ThreatEvaluator - 통합 위협 평가 인터페이스
 *
 * <p>
 * Enterprise 모듈에서 IntegratedThreatEvaluator 기능을 제공하는 인터페이스입니다.
 * Spring Boot AutoConfiguration을 통해 자동으로 주입됩니다.
 * </p>
 *
 * @since 0.1.0-ALPHA
 */
public interface ThreatEvaluator {

    /**
     * 통합 위협 평가 수행
     *
     * @param event 보안 이벤트
     * @return 위협 평가 결과
     */
    ThreatAssessment evaluateIntegrated(SecurityEvent event);
}
