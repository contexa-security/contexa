package io.contexa.demo.observation.learning.service;

import io.contexa.demo.observation.learning.dto.BaselineValueSnapshot;
import io.contexa.demo.observation.learning.dto.LearningSource;

public interface LearningObservationRecorder {

    void callReturned(LearningSource source, Boolean returned, String failureType);

    void writeReturned(LearningSource source, BaselineValueSnapshot submitted,
            BaselineValueSnapshot observed, String failureType);
}
