package io.contexa.contexaiam.aiam.labs;

import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacommon.domain.LabSpecialization;
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
}
