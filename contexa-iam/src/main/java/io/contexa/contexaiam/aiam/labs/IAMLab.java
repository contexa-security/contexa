package io.contexa.contexaiam.aiam.labs;

import io.contexa.contexacore.std.labs.AILab;
import io.contexa.contexacommon.domain.LabSpecialization;

public interface IAMLab<Req, Res> extends AILab<Req, Res> {

    LabSpecialization getSpecialization();

    default String getVersion() {
        return "1.0.0";
    }
}