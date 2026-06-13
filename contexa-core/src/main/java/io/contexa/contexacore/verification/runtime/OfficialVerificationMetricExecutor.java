package io.contexa.contexacore.verification.runtime;

public interface OfficialVerificationMetricExecutor<R extends OfficialVerificationRunView> {

    String metricCode();

    boolean ready();
}