package io.contexa.contexacore.std.pipeline.condition;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * 컨텍스트 검색 선택적 실행 조건
 *
 * 요청 특성 분석 결과 컨텍스트 검색이 필요한 경우에만 실행됩니다.
 * 간단한 분류 작업 등은 컨텍스트 검색을 건너뛰어 지연 시간을 단축합니다.
 *
 * 사용 예시:
 * - 단순 분류 작업: 컨텍스트 검색 생략 (30-50% 지연 시간 단축)
 * - 복잡한 분석: 컨텍스트 검색 수행
 */
@Slf4j
public class ContextRetrievalOptionalCondition<T extends DomainContext>
        implements PipelineStepCondition<T> {

    @Override
    public boolean shouldExecute(AIRequest<T> request, PipelineExecutionContext context) {
        // requiresContextRetrieval이 true일 때만 실행
        Boolean requiresContext = context.get("requires_context_retrieval", Boolean.class);

        if (requiresContext == null) {
            // 기본값: 안전하게 실행
            log.debug("[ContextRetrieval] 분석 정보 없음 - 기본 실행");
            return true;
        }

        log.debug("[ContextRetrieval] 컨텍스트 검색 필요: {} - 실행: {}",
                requiresContext, requiresContext);

        return requiresContext;
    }

    @Override
    public String getConditionDescription() {
        return "컨텍스트 검색 필요 시에만 실행";
    }
}
