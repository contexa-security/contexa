package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContextProvider;
import io.contexa.contexacore.autonomous.context.PromptContextComposer;
import io.contexa.contexacore.autonomous.mcp.McpSecurityContextProvider;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;

/**
 * @deprecated Legacy compatibility wrapper. Runtime prompt construction is standardized on
 * {@link SecurityDecisionStandardPromptTemplate}. New wiring must use the standard template directly.
 */
@Deprecated(forRemoval = false)
public class SecurityPromptTemplate extends SecurityDecisionStandardPromptTemplate {

    public SecurityPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            McpSecurityContextProvider mcpSecurityContextProvider,
            CanonicalSecurityContextProvider canonicalSecurityContextProvider,
            PromptContextComposer promptContextComposer) {
        super(
                eventEnricher,
                tieredStrategyProperties,
                mcpSecurityContextProvider,
                canonicalSecurityContextProvider,
                promptContextComposer);
    }

    public SecurityPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties) {
        super(eventEnricher, tieredStrategyProperties);
    }

    public SecurityPromptTemplate(
            SecurityEventEnricher eventEnricher,
            TieredStrategyProperties tieredStrategyProperties,
            McpSecurityContextProvider mcpSecurityContextProvider) {
        super(eventEnricher, tieredStrategyProperties, mcpSecurityContextProvider);
    }
}
