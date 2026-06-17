package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.replay.DeterministicReplayResult;

public interface RuntimeEvidenceReplayService {

    DeterministicReplayResult replay(String packageId);
}
