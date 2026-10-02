package io.contexa.demo.observation.prompt.service;

import io.contexa.contexacore.verification.capture.SealedEvidencePromptSnapshot;

public interface GeneratedPromptRecorder {

    void record(SealedEvidencePromptSnapshot snapshot);
}
