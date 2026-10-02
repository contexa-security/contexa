package io.contexa.demo.observation.pipeline.service;

import io.contexa.contexacore.std.llm.observation.LlmObservationContext;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;

public interface PipelineObservationRecorder {

    void record(LlmObservationContext source, PipelineExecutionContext context, String completion, String failureType);
}
