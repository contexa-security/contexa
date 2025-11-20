package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import reactor.core.publisher.Mono;

/**
 * PolicyEvolutionService - 정책 진화 서비스 인터페이스
 *
 * <p>
 * Enterprise 모듈에서 자율 정책 진화 기능을 제공하는 인터페이스입니다.
 * Spring Boot AutoConfiguration을 통해 자동으로 주입됩니다.
 * </p>
 *
 * @since 0.1.0-ALPHA
 */
public interface PolicyEvolutionService {

    /**
     * 이벤트로부터 정책 학습
     *
     * @param event 보안 이벤트
     * @param decision 결정 내용
     * @param outcome 결과
     * @return 학습 결과 Mono
     */
    Mono<?> learnFromEvent(SecurityEvent event, String decision, String outcome);

    /**
     * 정책 진화 수행
     *
     * @param event 보안 이벤트
     * @param assessment 위협 평가 결과
     */
    void evolvePolicy(SecurityEvent event, ThreatAssessment assessment);
}
