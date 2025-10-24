package io.contexa.contexacore.std.rag.debug;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.filter.converter.PrintFilterExpressionConverter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Filter Debug Interceptor
 *
 * VectorStore 검색 작업의 필터 표현식을 자동으로 시각화하여 로그에 출력합니다.
 *
 * 모든 similaritySearch() 호출을 가로채서:
 * 1. SearchRequest의 FilterExpression을 추출
 * 2. PrintFilterExpressionConverter로 사람이 읽을 수 있는 형식으로 변환
 * 3. DEBUG 레벨로 로그 출력
 *
 * 이를 통해:
 * - RagConfiguration의 필터 로직 검증
 * - ContextRetriever의 필터 조합 디버깅
 * - HCADSimilarityCalculator의 복잡한 필터 시각화
 * - AbstractVectorLabService의 필터 적용 확인
 * 등이 자동으로 이루어집니다.
 *
 * application.yml에서 활성화:
 * ```yaml
 * spring:
 *   ai:
 *     vectorstore:
 *       debug:
 *         filter-logging: true
 * ```
 *
 * @since 1.0.0
 */
@Slf4j
@Aspect
@Component
@ConditionalOnProperty(
    prefix = "spring.ai.vectorstore.debug",
    name = "filter-logging",
    havingValue = "true",
    matchIfMissing = false
)
public class FilterDebugInterceptor {

    private final PrintFilterExpressionConverter filterPrinter = new PrintFilterExpressionConverter();

    /**
     * similaritySearch() 메소드 가로채기
     *
     * 모든 패키지의 similaritySearch() 메소드를 가로챕니다:
     * - io.contexa.contexacore.std.rag.service.StandardVectorStoreService
     * - io.contexa.contexacore.std.rag.service.ObservableVectorStoreService
     * - io.contexa.contexacore.std.rag.service.AbstractVectorLabService
     * - io.contexa.contexacore.hcad.service.HCADSimilarityCalculator
     * - io.contexa.contexacore.autonomous.tiered.strategy.Layer*Strategy
     *
     * @param joinPoint AOP Join Point
     * @return 원본 메소드 실행 결과
     * @throws Throwable 원본 메소드에서 발생한 예외
     */
    @Around("execution(* io.contexa.contexacore..*.similaritySearch(..))")
    public Object debugFilter(ProceedingJoinPoint joinPoint) throws Throwable {
        Object[] args = joinPoint.getArgs();
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getTarget().getClass().getSimpleName();

        // SearchRequest 파라미터 찾기
        for (Object arg : args) {
            if (arg instanceof SearchRequest request) {
                debugSearchRequest(request, className, methodName);
                break;
            }
        }

        // 원본 메소드 실행
        return joinPoint.proceed();
    }

    /**
     * SearchRequest 디버깅 정보 출력
     *
     * @param request SearchRequest
     * @param className 호출한 클래스 이름
     * @param methodName 호출한 메소드 이름
     */
    private void debugSearchRequest(SearchRequest request, String className, String methodName) {
        if (!log.isDebugEnabled()) {
            return;
        }

        StringBuilder debugInfo = new StringBuilder();
        debugInfo.append(String.format("[VectorStore Filter Debug] %s.%s()\n", className, methodName));

        // 쿼리 정보
        if (request.getQuery() != null && !request.getQuery().isBlank()) {
            String truncatedQuery = request.getQuery().length() > 100
                ? request.getQuery().substring(0, 100) + "..."
                : request.getQuery();
            debugInfo.append(String.format("  Query: %s\n", truncatedQuery));
        }

        // Top-K
        debugInfo.append(String.format("  Top-K: %d\n", request.getTopK()));

        // 유사도 임계값
        debugInfo.append(String.format("  Similarity Threshold: %.3f\n", request.getSimilarityThreshold()));

        // 필터 표현식 (사람이 읽을 수 있는 형식으로 변환)
        if (request.getFilterExpression() != null) {
            try {
                String readableFilter = filterPrinter.convertExpression(request.getFilterExpression());
                debugInfo.append(String.format("  Filter Expression:\n    %s\n", readableFilter));

                // 필터 복잡도 분석
                int andCount = countOccurrences(readableFilter, "AND");
                int orCount = countOccurrences(readableFilter, "OR");
                int totalConditions = andCount + orCount + 1;

                debugInfo.append(String.format("  Filter Complexity: %d conditions (%d AND, %d OR)\n",
                    totalConditions, andCount, orCount));

            } catch (Exception e) {
                debugInfo.append(String.format("  Filter Expression: [Parse Error: %s]\n", e.getMessage()));
                debugInfo.append(String.format("  Raw Filter: %s\n", request.getFilterExpression()));
            }
        } else {
            debugInfo.append("  Filter Expression: [None]\n");
        }

        log.debug(debugInfo.toString());
    }

    /**
     * 문자열 내 특정 패턴 발생 횟수 계산
     */
    private int countOccurrences(String text, String pattern) {
        int count = 0;
        int index = 0;

        while ((index = text.indexOf(pattern, index)) != -1) {
            count++;
            index += pattern.length();
        }

        return count;
    }
}
