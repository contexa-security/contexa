package io.contexa.contexaiam.admin.promptquality.official.state;

import java.util.List;

public interface PromptQualityStateCatalog {

    List<PromptQualityStateDescriptor> descriptors();

    PromptQualityStateDescriptor describe(PromptQualityStateDimension dimension, String code);

    PromptQualityStateDescriptor resourceRequestObservation(boolean evidenceObserved, boolean decisionRecorded);

    PromptQualityStateDescriptor runtimeEvidence(boolean sealed, boolean integrityValid, boolean warningSignals);

    List<String> resourceOperationalActions(String operationalState, boolean promotable);
}
