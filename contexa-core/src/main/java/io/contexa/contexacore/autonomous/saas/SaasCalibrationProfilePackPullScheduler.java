package io.contexa.contexacore.autonomous.saas;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.scheduling.annotation.Scheduled;

public class SaasCalibrationProfilePackPullScheduler {

    private final SaasCalibrationProfilePackService calibrationProfilePackService;
    private final SaasForwardingProperties properties;

    public SaasCalibrationProfilePackPullScheduler(
            SaasCalibrationProfilePackService calibrationProfilePackService,
            SaasForwardingProperties properties) {
        this.calibrationProfilePackService = calibrationProfilePackService;
        this.properties = properties;
    }

    @Scheduled(
            initialDelayString = "",
            fixedDelayString = "")
    public void refreshCalibrationProfilePack() {
        if (!properties.isEnabled()
                || properties.getCalibrationProfile() == null
                || !properties.getCalibrationProfile().isEnabled()) {
            return;
        }
        calibrationProfilePackService.refresh();
    }
}
