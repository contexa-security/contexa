package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

/**
 * Abstract base class providing common utilities for all prompt templates.
 * <p>
 * This class extracts shared functionality between streaming and non-streaming
 * prompt templates, including:
 * <ul>
 *   <li>Natural language query extraction</li>
 *   <li>IAM data context extraction</li>
 *   <li>Context type checking</li>
 * </ul>
 * </p>
 *
 * @see AbstractStreamingPromptTemplate
 * @see AbstractStandardPromptTemplate
 */
public abstract class AbstractBasePromptTemplate implements PromptTemplate {

    /**
     * Standard parameter name for natural language queries.
     */
    protected static final String NATURAL_LANGUAGE_QUERY_PARAM = "naturalLanguageQuery";

    /**
     * Standard parameter name for IAM data context.
     */
    protected static final String IAM_DATA_CONTEXT_PARAM = "iamDataContext";

    /**
     * Extracts the natural language query from the request.
     * <p>
     * This method attempts to retrieve the query in the following order:
     * <ol>
     *   <li>From the request's {@code getNaturalLanguageQuery()} method</li>
     *   <li>From the request parameter {@code naturalLanguageQuery}</li>
     *   <li>Returns the default message if not found</li>
     * </ol>
     * </p>
     *
     * @param request the AI request containing the query
     * @param defaultMessage the default message to return if no query is found
     * @return the natural language query or the default message
     */
    protected String extractNaturalQuery(AIRequest<? extends DomainContext> request, String defaultMessage) {
        String naturalQuery = request.getNaturalLanguageQuery();
        if (naturalQuery != null && !naturalQuery.isBlank()) {
            return naturalQuery;
        }

        naturalQuery = request.getParameter(NATURAL_LANGUAGE_QUERY_PARAM, String.class);
        if (naturalQuery != null && !naturalQuery.isBlank()) {
            return naturalQuery;
        }

        return defaultMessage;
    }

    /**
     * Extracts the natural language query from the request with a standard default message.
     *
     * @param request the AI request containing the query
     * @return the natural language query or a default message
     */
    protected String extractNaturalQuery(AIRequest<? extends DomainContext> request) {
        return extractNaturalQuery(request, "Natural language query was not provided");
    }

    /**
     * Extracts and merges the IAM data context from the request with RAG context info.
     * <p>
     * This method combines both data sources for optimal LLM response quality:
     * <ul>
     *   <li>IAM data context: Real-time authorization status from database</li>
     *   <li>Context info: RAG retrieval results (similar query patterns)</li>
     * </ul>
     * </p>
     *
     * @param request the AI request containing the context
     * @param contextInfo RAG retrieval context information
     * @return merged context combining IAM data and RAG context
     */
    protected String extractIamDataContext(AIRequest<? extends DomainContext> request, String contextInfo) {
        String iamDataContext = request.getParameter(IAM_DATA_CONTEXT_PARAM, String.class);

        // Both exist: merge for optimal response quality
        if (iamDataContext != null && !iamDataContext.isBlank()
                && contextInfo != null && !contextInfo.isBlank()) {
            return iamDataContext + "\n\n--- RAG Context (Similar Query Patterns) ---\n" + contextInfo;
        }

        // Only IAM data: sufficient for basic response
        if (iamDataContext != null && !iamDataContext.isBlank()) {
            return iamDataContext;
        }

        // Only RAG context: fallback
        return contextInfo;
    }

    /**
     * Checks if the request context is of the specified type.
     *
     * @param request the AI request to check
     * @param contextType the expected context type
     * @return true if the context matches the specified type
     */
    protected boolean isContextType(AIRequest<? extends DomainContext> request, Class<? extends DomainContext> contextType) {
        return request.getContext() != null && contextType.isInstance(request.getContext());
    }
}
