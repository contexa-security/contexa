package io.contexa.contexacore.autonomous.orchestrator.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;

/**
 * 보안 이벤트 처리 전략 인터페이스
 *
 * Strategy 패턴을 적용하여 각 ProcessingMode별 처리 로직을 캡슐화
 * OCP (Open/Closed Principle) 준수를 위해 새로운 처리 모드 추가 시
 * 기존 코드 수정 없이 새로운 전략만 추가
 *
 * @author AI3Security
 * @since 1.0
 */
public interface ProcessingStrategy {

    /**
     * 보안 이벤트 처리 실행
     *
     * @param context 보안 이벤트 컨텍스트
     * @return 처리 결과
     */
    ProcessingResult process(SecurityEventContext context);

    /**
     * 지원하는 처리 모드 (기본 모드)
     *
     * @return 이 전략이 처리하는 기본 ProcessingMode
     */
    ProcessingMode getSupportedMode();

    /**
     * 특정 ProcessingMode를 지원하는지 확인
     *
     * 하나의 Strategy가 여러 ProcessingMode를 처리할 수 있도록 확장 지원
     * 기본 구현은 getSupportedMode()와 비교
     *
     * @param mode 확인할 ProcessingMode
     * @return 지원 여부
     */
    default boolean supports(ProcessingMode mode) {
        return mode == getSupportedMode();
    }

    /**
     * 전략 실행 가능 여부 확인
     *
     * @param context 보안 이벤트 컨텍스트
     * @return 실행 가능 여부
     */
    default boolean canProcess(SecurityEventContext context) {
        ProcessingMode mode = (ProcessingMode) context.getMetadata().get("processingMode");
        return mode != null && supports(mode);
    }

    /**
     * 전략 이름
     *
     * @return 전략 이름
     */
    default String getName() {
        return getSupportedMode().toString() + "Strategy";
    }
}