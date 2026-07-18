package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.Objects;

public final class OfficialVerificationExecutionWriters {

    private final OfficialVerificationReverificationWriter reverificationWriter;
    private final OfficialVerificationMetricExecutionReferenceWriter metricExecutionReferenceWriter;

    public OfficialVerificationExecutionWriters(
            OfficialVerificationReverificationWriter reverificationWriter,
            OfficialVerificationMetricExecutionReferenceWriter metricExecutionReferenceWriter) {
        this.reverificationWriter = Objects.requireNonNull(reverificationWriter, "reverificationWriter");
        this.metricExecutionReferenceWriter = Objects.requireNonNull(
                metricExecutionReferenceWriter,
                "metricExecutionReferenceWriter");
    }

    public OfficialVerificationReverificationWriter reverification() {
        return reverificationWriter;
    }

    public OfficialVerificationMetricExecutionReferenceWriter metricExecutionReference() {
        return metricExecutionReferenceWriter;
    }
}
