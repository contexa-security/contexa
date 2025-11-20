package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import reactor.core.publisher.Mono;

/**
 * LearningEngine - 학습 엔진 인터페이스
 *
 * <p>
 * Enterprise 모듈에서 AI 기반 학습 기능을 제공하는 인터페이스입니다.
 * Spring Boot AutoConfiguration을 통해 자동으로 주입됩니다.
 * </p>
 *
 * @since 0.1.0-ALPHA
 */
public interface LearningEngine {

    /**
     * 이벤트로부터 학습
     *
     * @param event 보안 이벤트
     * @param response 대응 내용
     * @param effectiveness 효과성 점수
     * @return 학습 결과 Mono
     */
    Mono<?> learnFromEvent(SecurityEvent event, String response, double effectiveness);

    /**
     * 학습 내용 적용하여 예측 수행
     *
     * @param event 보안 이벤트
     * @return 예측 결과 Mono
     */
    Mono<?> applyLearning(SecurityEvent event);
}
