package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;

public interface OfficialPromptFieldDefinitionWriter {

    void upsertFrom(SealedEvidencePackage evidencePackage);
}
