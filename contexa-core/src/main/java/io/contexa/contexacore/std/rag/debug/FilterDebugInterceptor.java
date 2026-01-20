package io.contexa.contexacore.std.rag.debug;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.filter.converter.PrintFilterExpressionConverter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;


@Slf4j
@Aspect
@ConditionalOnProperty(
    prefix = "spring.ai.vectorstore.debug",
    name = "filter-logging",
    havingValue = "true",
    matchIfMissing = false
)
public class FilterDebugInterceptor {

    private final PrintFilterExpressionConverter filterPrinter = new PrintFilterExpressionConverter();

    
    @Around("execution(* io.contexa.contexacore..*.similaritySearch(..))")
    public Object debugFilter(ProceedingJoinPoint joinPoint) throws Throwable {
        Object[] args = joinPoint.getArgs();
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getTarget().getClass().getSimpleName();

        
        for (Object arg : args) {
            if (arg instanceof SearchRequest request) {
                debugSearchRequest(request, className, methodName);
                break;
            }
        }

        
        return joinPoint.proceed();
    }

    
    private void debugSearchRequest(SearchRequest request, String className, String methodName) {
        if (!log.isDebugEnabled()) {
            return;
        }

        StringBuilder debugInfo = new StringBuilder();
        debugInfo.append(String.format("[VectorStore Filter Debug] %s.%s()\n", className, methodName));

        
        if (request.getQuery() != null && !request.getQuery().isBlank()) {
            String truncatedQuery = request.getQuery().length() > 100
                ? request.getQuery().substring(0, 100) + "..."
                : request.getQuery();
            debugInfo.append(String.format("  Query: %s\n", truncatedQuery));
        }

        
        debugInfo.append(String.format("  Top-K: %d\n", request.getTopK()));

        
        debugInfo.append(String.format("  Similarity Threshold: %.3f\n", request.getSimilarityThreshold()));

        
        if (request.getFilterExpression() != null) {
            try {
                String readableFilter = filterPrinter.convertExpression(request.getFilterExpression());
                debugInfo.append(String.format("  Filter Expression:\n    %s\n", readableFilter));

                
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
