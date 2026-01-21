package io.contexa.contexacore.std.rag.observation;

import io.micrometer.common.KeyValue;
import io.micrometer.common.KeyValues;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.vectorstore.observation.VectorStoreObservationContext;
import org.springframework.ai.vectorstore.observation.VectorStoreObservationConvention;

@Slf4j
public class SecurityVectorStoreObservationConvention implements VectorStoreObservationConvention {

    @Override
    public String getName() {
        return "spring.ai.vectorstore";
    }

    @Override
    public KeyValues getLowCardinalityKeyValues(VectorStoreObservationContext context) {
        return KeyValues.of(
            KeyValue.of("vector.store.operation", extractOperationType(context)),
            KeyValue.of("vector.store.type", "pgvector"),
            KeyValue.of("vector.store.document.type", extractDocumentType(context)),
            KeyValue.of("vector.store.status", context.getError() != null ? "failure" : "success")
        );
    }

    @Override
    public KeyValues getHighCardinalityKeyValues(VectorStoreObservationContext context) {
        KeyValues keyValues = KeyValues.empty();

        if (context.getQueryRequest() != null && context.getQueryRequest().getQuery() != null) {
            String query = context.getQueryRequest().getQuery();
            String truncatedQuery = query.length() > 100
                ? query.substring(0, 100) + "..."
                : query;
            keyValues = keyValues.and(KeyValue.of("vector.store.query", truncatedQuery));
        }

        if (context.getQueryRequest() != null && context.getQueryRequest().getFilterExpression() != null) {
            int complexity = calculateFilterComplexity(
                context.getQueryRequest().getFilterExpression().toString()
            );
            keyValues = keyValues.and(KeyValue.of("vector.store.filter.complexity", String.valueOf(complexity)));
        }

        if (context.getQueryResponse() != null) {
            keyValues = keyValues.and(
                KeyValue.of("vector.store.result.count", String.valueOf(context.getQueryResponse().size()))
            );
        }

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

    private String extractOperationType(VectorStoreObservationContext context) {
        if (context.getQueryRequest() != null) {
            return "QUERY";
        }

        return "UNKNOWN";
    }

    private String extractDocumentType(VectorStoreObservationContext context) {
        try {
            if (context.getQueryRequest() != null
                && context.getQueryRequest().getFilterExpression() != null) {

                String filterStr = context.getQueryRequest().getFilterExpression().toString();

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
                    }

        return "unknown";
    }

    private int calculateFilterComplexity(String filterExpression) {
        int andCount = countOccurrences(filterExpression, "AND");
        int orCount = countOccurrences(filterExpression, "OR");
        return andCount + orCount + 1;
    }

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
