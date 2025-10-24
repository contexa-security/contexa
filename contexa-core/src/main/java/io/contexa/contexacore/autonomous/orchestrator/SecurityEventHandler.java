package io.contexa.contexacore.autonomous.orchestrator;

import io.contexa.contexacore.autonomous.domain.SecurityEventContext;

/**
 * 보안 이벤트 처리 핸들러 인터페이스
 *
 * Chain of Responsibility 패턴을 구현하여 보안 이벤트 처리의
 * 각 단계를 독립적으로 처리합니다.
 *
 * 특징:
 * - 각 핸들러는 단일 책임 원칙(SRP)을 준수
 * - 새로운 처리 단계 추가 시 기존 코드 수정 불필요 (OCP)
 * - 처리 중단 조건을 반환값으로 제어
 *
 * @author AI3Security
 * @since 1.0
 */
public interface SecurityEventHandler {

    /**
     * 보안 이벤트 처리 단계 실행
     *
     * @param context 보안 이벤트 컨텍스트 (모든 처리 정보 포함)
     * @return true면 다음 핸들러 실행, false면 체인 중단
     */
    boolean handle(SecurityEventContext context);

    /**
     * 핸들러 이름 반환 (로깅 및 디버깅용)
     *
     * @return 핸들러 이름
     */
    String getName();

    /**
     * 핸들러 실행 순서 (낮은 값이 먼저 실행)
     *
     * @return 실행 순서
     */
    default int getOrder() {
        return 100;
    }

    /**
     * 핸들러 실행 가능 여부 확인
     *
     * @param context 보안 이벤트 컨텍스트
     * @return 실행 가능 여부
     */
    default boolean canHandle(SecurityEventContext context) {
        return context != null &&
               context.getSecurityEvent() != null &&
               context.getProcessingStatus() != SecurityEventContext.ProcessingStatus.FAILED;
    }

    /**
     * 에러 발생 시 처리
     *
     * @param context 보안 이벤트 컨텍스트
     * @param error 발생한 예외
     */
    default void handleError(SecurityEventContext context, Exception error) {
        context.markAsFailed(String.format("[%s] %s", getName(), error.getMessage()));
    }
}