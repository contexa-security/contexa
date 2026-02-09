package io.contexa.contexaiam.aiam.labs;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class AbstractIAMLab<Req,Res> extends AbstractAILab<Req, Res> implements IAMLab<Req,Res> {

    private final String labVersion;
    private final LabSpecialization specialization;

    protected AbstractIAMLab(String labName, String labVersion, LabSpecialization specialization) {
        super(labName);
        this.labVersion = labVersion;
        this.specialization = specialization;
    }

    @Override
    public LabSpecialization getSpecialization() {
        return specialization;
    }

    @Override
    public String getVersion() {
        return labVersion;
    }

    @Override
    protected void postProcess(Req request, Res result) {
        super.postProcess(request, result);

        if (result != null) {
                    }
    }

    protected PipelineConfiguration createPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(300)
                .build();
    }

    protected PipelineConfiguration createStreamPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .enableStreaming(true)
                .timeoutSeconds(300)
                .build();
    }
}
