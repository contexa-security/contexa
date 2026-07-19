package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.verification.capture.PromptEvidenceMetadataProvider;
import io.contexa.contexacore.verification.capture.VerificationCaptureContext;
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

        return buildMetadata(PromptSourceContextSnapshotFactory.capture(securityDecisionContext), promptResult);
    }

    @Override
    public Map<String, Object> buildMetadata(
            VerificationCaptureContext captureContext,
            PromptGenerationResult promptResult
    ) {
        return buildMetadata(PromptSourceContextSnapshotFactory.capture(captureContext), promptResult);
    }

    private Map<String, Object> buildMetadata(
            PromptSourceContextSnapshot sourceSnapshot,
            PromptGenerationResult promptResult
    ) {
        Map<String, Object> metadata = new LinkedHashMap<>();
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
