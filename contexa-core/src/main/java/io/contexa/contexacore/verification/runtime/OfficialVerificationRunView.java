package io.contexa.contexacore.verification.runtime;

import java.util.List;
import java.util.Map;

public interface OfficialVerificationRunView {

    String runId();

    int round();

    String endpointKey();

    String endpointLabel();

    String requestId();

    double score();

    int passedChecks();

    int totalChecks();

    Long processingTimeMs();

    String state();

    String stateTone();

    String message();

    String startedAt();

    String completedAt();

    List<? extends OfficialVerificationCheckResultView> checks();

    Map<String, String> requestFacts();

    Map<String, String> eventFacts();

    Map<String, String> promptFacts();

    Map<String, String> analysisFacts();

    List<? extends OfficialVerificationEventItemView> events();

    Map<String, Object> rawEvidence();
}