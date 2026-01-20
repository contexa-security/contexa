package io.contexa.contexaiam.aiam.labs;

import io.opentelemetry.api.trace.Tracer;
import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacommon.domain.LabSpecialization;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public abstract class AbstractIAMLab<Req,Res> extends AbstractAILab<Req, Res> implements IAMLab<Req,Res> {

    private final String labVersion;
    private final LabSpecialization specialization;

    
    protected AbstractIAMLab(Tracer tracer, String labName, String labVersion, LabSpecialization specialization) {
        super(labName, tracer);  
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
            log.debug("IAM Lab {} processed request with result type: {}",
                    getLabName(), result.getClass().getSimpleName());
        }
    }
}
