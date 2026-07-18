package io.contexa.contexacore.verification.runtime.sealed.testsupport;

import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRequest;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationResult;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public abstract class OfficialSealedEvidenceVerificationRuntimeContract {

    protected abstract OfficialSealedEvidenceVerificationRuntime runtime();

    protected abstract String packageId();

    @Test
    protected final void executeAndFindExposeEquivalentOfficialRunContract() {
        OfficialSealedEvidenceVerificationRuntime runtime = runtime();

        OfficialSealedEvidenceVerificationResult executed = runtime.executeAll(
                new OfficialSealedEvidenceVerificationRequest(packageId(), "contract-operator"));
        OfficialSealedEvidenceVerificationResult found = runtime.findByPackageId(packageId());

        assertThat(executed.packageId()).isEqualTo(packageId());
        assertThat(found.packageId()).isEqualTo(executed.packageId());
        assertThat(found.aggregateRunId()).isEqualTo(executed.aggregateRunId());
        assertThat(found.integrityValid()).isEqualTo(executed.integrityValid());
        assertThat(found.runs()).isNotEmpty();
        assertThat(signatures(found.runs()))
                .containsExactlyInAnyOrderElementsOf(signatures(executed.runs()));
    }

    private List<RunSignature> signatures(List<? extends OfficialVerificationRunView> runs) {
        return runs.stream().map(this::signature).toList();
    }

    private RunSignature signature(OfficialVerificationRunView run) {
        return new RunSignature(
                run.endpointKey(),
                run.round(),
                run.score(),
                run.passedChecks(),
                run.totalChecks(),
                run.state(),
                checkSignatures(run.checks()));
    }

    private List<CheckSignature> checkSignatures(
            List<? extends OfficialVerificationCheckResultView> checks) {
        return checks.stream()
                .map(check -> new CheckSignature(check.checkCode(), check.pass(), check.source()))
                .toList();
    }

    private record RunSignature(
            String metricCode,
            int round,
            double score,
            int passedChecks,
            int totalChecks,
            String state,
            List<CheckSignature> checks) {
    }

    private record CheckSignature(String checkCode, boolean passed, String source) {
    }
}