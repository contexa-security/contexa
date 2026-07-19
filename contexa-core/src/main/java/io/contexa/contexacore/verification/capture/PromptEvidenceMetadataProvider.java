package io.contexa.contexacore.verification.capture;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;

import java.util.Map;

public interface PromptEvidenceMetadataProvider {
    Map<String, Object> buildMetadata(DomainContext context, PromptGenerationResult promptResult);

    default Map<String, Object> buildMetadata(
            VerificationCaptureContext captureContext,
            PromptGenerationResult promptResult
    ) {
        return buildMetadata(captureContext == null ? null : captureContext.domainContext(), promptResult);
    }
}
