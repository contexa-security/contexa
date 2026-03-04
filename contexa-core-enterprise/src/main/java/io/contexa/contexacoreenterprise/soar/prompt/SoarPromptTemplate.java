package io.contexa.contexacoreenterprise.soar.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class SoarPromptTemplate implements PromptTemplate {

    private static final String TOOL_EXECUTION_ROLE = """
        You are a SOAR security tool execution system.

        Current phase: Tool function calling phase

        Important instructions:
        1. Directly call the provided tool functions
        2. Do not generate text responses
        3. Do not generate JSON strings
        4. Only perform function calling

        Available security tools:
        - ip_blocking: Block IP addresses
        - network_isolation: Network isolation
        - process_kill: Terminate malicious processes
        - session_termination: Session termination
        - file_quarantine: File quarantine

        Each tool is provided as a function; call it with appropriate parameters.
        You must perform actual function calls,
        not generate tool descriptions or JSON text.
        """;

    private static final String RESPONSE_GENERATION_ROLE = """
        You are a SOAR security analysis system.

        Current phase: Final analysis and response generation phase

        Tool execution is complete. Now perform a comprehensive security analysis based on the collected data.

        Response generation rules:
        1. Comprehensively analyze tool execution results
        2. Evaluate threat levels
        3. Provide specific recommended actions
        4. Generate a valid JSON-formatted SoarResponse

        Important: Do not make additional tool calls in this phase.
        """;

    @Override
    public Class<?> getAIGenerationType() {
        return SoarResponse.class;
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("Soar");
    }

    @Override
    public String generateSystemPrompt(AIRequest<?> request, String systemMetadata) {
        StringBuilder prompt = new StringBuilder();

        // Detect mode from request context and apply role prompt
        if (request != null && request.getContext() instanceof SoarContext) {
            prompt.append(TOOL_EXECUTION_ROLE);
        } else {
            prompt.append(RESPONSE_GENERATION_ROLE);
        }

        if (systemMetadata != null && !systemMetadata.trim().isEmpty()) {
            prompt.append("\n\nSystem Context: ");
            prompt.append(systemMetadata);
        }

        return prompt.toString();
    }

    @Override
    public String generateUserPrompt(AIRequest<?> request, String contextInfo) {
        StringBuilder prompt = new StringBuilder();

        TemplateType templateType = request.getPromptTemplate();
        if (templateType != null && !templateType.name().isEmpty()) {
            prompt.append(templateType);
            prompt.append("\n");
        }

        if (contextInfo != null && !contextInfo.trim().isEmpty()) {
            prompt.append("\nContext: ");
            prompt.append(contextInfo);
            prompt.append("\n");
        }

        if (request.getContext() instanceof SoarContext soarContext) {
            if (soarContext.getIncidentId() != null || soarContext.getThreatLevel() != null) {
                prompt.append("\n");
                appendSoarContext(prompt, soarContext);
            }
        }
        
        return prompt.toString();
    }

    private void appendSoarContext(StringBuilder prompt, SoarContext context) {
        if (context.getIncidentId() != null) {
            prompt.append("Incident ID: ").append(context.getIncidentId()).append("\n");
        }

        if (context.getThreatLevel() != null) {
            prompt.append("Threat Level: ").append(context.getThreatLevel()).append("\n");
        }

        if (context.getAffectedAssets() != null && !context.getAffectedAssets().isEmpty()) {
            prompt.append("Affected Assets: ").append(
                String.join(", ", context.getAffectedAssets())
            ).append("\n");
        }
    }

}