package io.contexa.contexacore.verification.replay;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;

/**
 * Result of a deterministic replay: compares a reassembled prompt
 * against the original sealed prompt to verify prompt assembly determinism.
 */
public record DeterministicReplayResult(
        String packageId,
        boolean identical,
        String originalPromptHash,
        String reconstructedPromptHash,
        int checksRun,
        int checksPassed,
        List<String> diffSummary,
        List<DiffSection> systemPromptDiff,
        List<DiffSection> userPromptDiff,
        Instant replayedAt
) {

    public DeterministicReplayResult {
        diffSummary = diffSummary == null ? List.of() : List.copyOf(diffSummary);
        systemPromptDiff = systemPromptDiff == null ? List.of() : List.copyOf(systemPromptDiff);
        userPromptDiff = userPromptDiff == null ? List.of() : List.copyOf(userPromptDiff);
    }

    @JsonProperty("passRate")
    public double passRate() {
        if (checksRun == 0) {
            return 0.0;
        }
        return (checksPassed * 100.0) / checksRun;
    }
}
