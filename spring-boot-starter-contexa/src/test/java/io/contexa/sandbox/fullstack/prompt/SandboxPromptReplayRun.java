package io.contexa.sandbox.fullstack.prompt;

import java.util.List;

/**
 * 동일 사용자에 대한 full-stack replay 실행 묶음.
 *
 * 핵심:
 * - 공식 benchmark v1은 1차/2차/3차를 기준으로 측정한다.
 * - 장기 benchmark는 N차까지 반복 실행할 수 있어야 하므로 전체 round 목록도 함께 보존한다.
 * - first/second/third accessor는 기존 3회 검증 코드와의 호환을 위해 유지한다.
 */
public record SandboxPromptReplayRun(
        String benchmarkRunId,
        String username,
        String scenarioKey,
        String experimentGroup,
        SandboxPromptReplayScenario scenario,
        List<SandboxPromptReplayRound> rounds) {

    public SandboxPromptReplayRun {
        rounds = rounds == null ? List.of() : List.copyOf(rounds);
        if (rounds.size() < 3) {
            throw new IllegalArgumentException("SandboxPromptReplayRun requires at least 3 rounds");
        }
    }

    public SandboxPromptReplayRound firstRound() {
        return rounds.get(0);
    }

    public SandboxPromptReplayRound secondRound() {
        return rounds.get(1);
    }

    public SandboxPromptReplayRound thirdRound() {
        return rounds.get(2);
    }

    public SandboxPromptReplayRound round(int oneBasedRoundNumber) {
        int index = oneBasedRoundNumber - 1;
        if (index < 0 || index >= rounds.size()) {
            throw new IllegalArgumentException("Round index out of bounds: " + oneBasedRoundNumber);
        }
        return rounds.get(index);
    }
}
