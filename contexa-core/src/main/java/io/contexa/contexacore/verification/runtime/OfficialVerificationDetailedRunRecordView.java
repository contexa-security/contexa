package io.contexa.contexacore.verification.runtime;

import java.util.List;
import java.util.Map;

public interface OfficialVerificationDetailedRunRecordView<C extends OfficialVerificationCheckResultView, E extends OfficialVerificationEventItemView> extends OfficialVerificationRunView {

    @Override
    List<C> checks();

    @Override
    Map<String, String> requestFacts();

    @Override
    Map<String, String> eventFacts();

    @Override
    Map<String, String> promptFacts();

    @Override
    Map<String, String> analysisFacts();

    @Override
    List<E> events();

    @Override
    Map<String, Object> rawEvidence();
}