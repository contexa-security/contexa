package io.contexa.contexacore.std.rag.observation;

import io.micrometer.common.KeyValue;
import io.micrometer.common.KeyValues;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.vectorstore.observation.VectorStoreObservationContext;
import org.springframework.ai.vectorstore.observation.VectorStoreObservationConvention;

/**
 * Security VectorStore Observation Convention
 *
 * Spring AI VectorStoreObservationConvention을 구현하여
 * AI3Security 플랫폼 전용 VectorStore 메트릭을 수집합니다.
 *
 * DefaultVectorStoreObservationConvention과 동일한 방식으로 구현하되,
 * 보안 플랫폼 특화 메트릭을 추가합니다.
 *
 * Low Cardinality Keys (집계 가능):
 * - vector.store.operation: 작업 타입 (ADD, QUERY, DELETE)
 * - vector.store.type: pgvector
 * - vector.store.document.type: threat, behavior, risk_assessment, policy
 * - vector.store.status: success, failure
 *
 * High Cardinality Keys (디버깅용):
 * - vector.store.query: 검색 쿼리 (truncated)
 * - vector.store.filter.complexity: 필터 복잡도
 * - vector.store.result.count: 검색 결과 개수
 *
 * @Component 제거: VectorStoreObservationConfig에서 @Bean으로 명시적 등록
 * @since 1.0.0
 */
@Slf4j
public class SecurityVectorStoreObservationConvention implements VectorStoreObservationConvention {

    /**
     * Observation Name
     *
     * Spring AI 표준: "spring.ai.vectorstore"
     *
     * @param context VectorStore Observation Context
     * @return Observation 이름
     */
    @Override
    public String getName() {
        return "spring.ai.vectorstore";
    }

    /**
     * Low Cardinality Key Values
     *
     * Prometheus/Grafana에서 집계 가능한 메트릭
     *
     * @param context VectorStore Observation Context
     * @return Low Cardinality KeyValues
     */
    @Override
    public KeyValues getLowCardinalityKeyValues(VectorStoreObservationContext context) {
        return KeyValues.of(
            KeyValue.of("vector.store.operation", extractOperationType(context)),
            KeyValue.of("vector.store.type", "pgvector"),
            KeyValue.of("vector.store.document.type", extractDocumentType(context)),
            KeyValue.of("vector.store.status", context.getError() != null ? "failure" : "success")
        );
    }

    /**
     * High Cardinality Key Values
     *
     * 디버깅에 유용하지만 집계는 어려운 메트릭
     *
     * @param context VectorStore Observation Context
     * @return High Cardinality KeyValues
     */
    @Override
    public KeyValues getHighCardinalityKeyValues(VectorStoreObservationContext context) {
        KeyValues keyValues = KeyValues.empty();

        // 쿼리 문자열 (100자 제한)
        if (context.getQueryRequest() != null && context.getQueryRequest().getQuery() != null) {
            String query = context.getQueryRequest().getQuery();
            String truncatedQuery = query.length() > 100
                ? query.substring(0, 100) + "..."
                : query;
            keyValues = keyValues.and(KeyValue.of("vector.store.query", truncatedQuery));
        }

        // 필터 복잡도
        if (context.getQueryRequest() != null && context.getQueryRequest().getFilterExpression() != null) {
            int complexity = calculateFilterComplexity(
                context.getQueryRequest().getFilterExpression().toString()
            );
            keyValues = keyValues.and(KeyValue.of("vector.store.filter.complexity", String.valueOf(complexity)));
        }

        // 검색 결과 개수
        if (context.getQueryResponse() != null) {
            keyValues = keyValues.and(
                KeyValue.of("vector.store.result.count", String.valueOf(context.getQueryResponse().size()))
            );
        }

        // 에러 정보
        if (context.getError() != null) {
            keyValues = keyValues.and(
                KeyValue.of("vector.store.error.type", context.getError().getClass().getSimpleName())
            );
            if (context.getError().getMessage() != null) {
                keyValues = keyValues.and(
                    KeyValue.of("vector.store.error.message", context.getError().getMessage())
                );
            }
        }

        return keyValues;
    }

    /**
     * 작업 타입 추출
     *
     * @param context Observation Context
     * @return 작업 타입 (ADD, QUERY, DELETE, UNKNOWN)
     */
    private String extractOperationType(VectorStoreObservationContext context) {
        if (context.getQueryRequest() != null) {
            return "QUERY";
        }
        // ADD나 DELETE는 Spring AI Context에서 직접 구분하기 어려움
        // 기본값 반환
        return "UNKNOWN";
    }

    /**
     * 문서 타입 추출
     *
     * FilterExpression에서 documentType 메타데이터를 파싱
     *
     * @param context Observation Context
     * @return 문서 타입 (threat, behavior, risk_assessment, policy, unknown)
     */
    private String extractDocumentType(VectorStoreObservationContext context) {
        try {
            if (context.getQueryRequest() != null
                && context.getQueryRequest().getFilterExpression() != null) {

                String filterStr = context.getQueryRequest().getFilterExpression().toString();

                // documentType 추출
                if (filterStr.contains("documentType")) {
                    int start = filterStr.indexOf("documentType");
                    int end = Math.min(filterStr.length(), start + 50);
                    String segment = filterStr.substring(start, end);

                    if (segment.contains("threat")) return "threat";
                    if (segment.contains("behavior")) return "behavior";
                    if (segment.contains("risk_assessment")) return "risk_assessment";
                    if (segment.contains("policy")) return "policy";
                }
            }
        } catch (Exception e) {
            log.debug("Failed to extract document type from filter expression", e);
        }

        return "unknown";
    }

    /**
     * 필터 복잡도 계산
     *
     * AND/OR 연산자 개수로 복잡도 추정
     *
     * @param filterExpression 필터 표현식 문자열
     * @return 복잡도 (조건 개수)
     */
    private int calculateFilterComplexity(String filterExpression) {
        int andCount = countOccurrences(filterExpression, "AND");
        int orCount = countOccurrences(filterExpression, "OR");
        return andCount + orCount + 1;
    }

    /**
     * 문자열 내 패턴 발생 횟수 계산
     *
     * @param text 검색 대상 문자열
     * @param pattern 검색 패턴
     * @return 발생 횟수
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
