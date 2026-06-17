package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.replay.DeterministicReplayResult;
import io.contexa.contexacore.verification.replay.DeterministicReplayService;

public class DefaultRuntimeEvidenceReplayService implements RuntimeEvidenceReplayService {

    private final DeterministicReplayService replayService;

    public DefaultRuntimeEvidenceReplayService(DeterministicReplayService replayService) {
        this.replayService = replayService;
    }

    @Override
    public DeterministicReplayResult replay(String packageId) {
        return replayService.replay(packageId);
    }
}

