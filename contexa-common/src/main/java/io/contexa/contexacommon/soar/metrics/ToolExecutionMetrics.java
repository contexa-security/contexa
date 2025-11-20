package io.contexa.contexacommon.soar.metrics;

/**
 * Tool Execution Metrics Interface
 *
 * <p>
 * Core와 Enterprise 사이의 SOAR 도구 실행 메트릭 인터페이스입니다.
 * Enterprise가 있으면 실제 메트릭이 수집되고, 없으면 아무 동작 안 함.
 * </p>
 *
 * @since 0.1.1
 */
public interface ToolExecutionMetrics {

    /**
     * 필터링된 도구 기록
     *
     * @param toolName 도구 이름
     * @param reason 필터링 사유
     */
    void recordFiltered(String toolName, String reason);
}
