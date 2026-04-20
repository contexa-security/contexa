package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("ResourceNamingTemplate schema, governance, batch size")
class ResourceNamingTemplateSchemaAndGovernanceTest {

    private ResourceNamingTemplate template;

    @BeforeEach
    void setUp() {
        template = new ResourceNamingTemplate();
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private AIRequest<? extends DomainContext> request(List<String> identifiers) {
        AIRequest req = mock(AIRequest.class);
        when(req.getParameter("identifiers", List.class)).thenReturn(identifiers);
        return req;
    }

    @Test
    @DisplayName("System prompt schema block communicates friendlyName/description length and confidence range")
    void systemPrompt_advertisesFieldConstraints() {
        String systemPrompt = template.generateSystemPrompt(request(List.of("/api/x")), null);

        assertThat(systemPrompt)
                .as("schema must declare friendlyName length constraint")
                .contains("friendlyName")
                .contains("50");
        assertThat(systemPrompt)
                .as("schema must declare description length constraint")
                .contains("description")
                .contains("300");
        assertThat(systemPrompt)
                .as("schema must declare confidence range")
                .contains("confidence")
                .contains("0.0")
                .contains("1.0");
    }

    @Test
    @DisplayName("Governance descriptor overrides default owner and version for the ResourceNaming prompt")
    void governanceDescriptor_overridesOwnerAndVersion() {
        PromptGovernanceDescriptor descriptor = template.getPromptGovernanceDescriptor();

        assertThat(descriptor.owner())
                .as("owner must be explicitly assigned for audit purposes")
                .containsIgnoringCase("IAM");
        assertThat(descriptor.promptVersion())
                .as("version must follow semantic versioning")
                .matches("\\d+\\.\\d+\\.\\d+");
    }

    @Test
    @DisplayName("Batch larger than MAX_BATCH_SIZE (20) emits an error log without throwing")
    void batchSize_over20_doesNotThrow() {
        List<String> oversized = IntStream.range(0, 25)
                .mapToObj(i -> "/api/resource-" + i)
                .toList();

        String userPrompt = template.generateUserPrompt(request(oversized), null);

        assertThat(userPrompt).contains("[RESOURCE_START_25]", "[RESOURCE_END_25]");
    }
}
