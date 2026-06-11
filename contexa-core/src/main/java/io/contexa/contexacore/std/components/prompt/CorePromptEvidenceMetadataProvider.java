package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.verification.capture.PromptEvidenceMetadataProvider;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class CorePromptEvidenceMetadataProvider implements PromptEvidenceMetadataProvider {

    @Override
    public Map<String, Object> buildMetadata(DomainContext context, PromptGenerationResult promptResult) {
        if (!(context instanceof SecurityDecisionContext securityDecisionContext)) {
            return Map.of();
        }

        Map<String, Object> metadata = new LinkedHashMap<>();
        PromptSourceContextSnapshot sourceSnapshot = PromptSourceContextSnapshotFactory.capture(securityDecisionContext);
        PromptFieldLineageAnalysis fieldLineage = PromptFieldLineageAnalyzer.analyze(
                promptResult.getRawUserPrompt(),
                promptResult.getUserPrompt());
        PromptFieldStateLedger fieldStateLedger = PromptFieldStateLedgerFactory.create(sourceSnapshot, fieldLineage);

        metadata.putAll(sourceSnapshot.toMetadataMap());
        metadata.putAll(fieldLineage.toMetadataMap());
        metadata.putAll(fieldStateLedger.toMetadataMap());
        return metadata;
    }
}
