package io.contexa.demo.observation.prompt.service;

import io.contexa.contexacore.verification.capture.SealedEvidencePromptSnapshot;
import io.contexa.demo.observation.prompt.dto.PromptContextEvidence;

public interface PromptContextProjection {

    PromptContextEvidence project(SealedEvidencePromptSnapshot snapshot);
}
