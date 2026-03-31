package io.contexa.sandbox.fullstack.prompt;

public enum SandboxDecisionMetric {
    CDC("CDC", "Context-to-Decision Calibration", 95.0d, true),
    ERA("ERA", "Evidence-Reason Alignment", 95.0d, true),
    SUHR("SUHR", "Safe-Uncertainty Handling Rate", 95.0d, true);

    private final String key;
    private final String displayName;
    private final double successThreshold;
    private final boolean higherIsBetter;

    SandboxDecisionMetric(String key, String displayName, double successThreshold, boolean higherIsBetter) {
        this.key = key;
        this.displayName = displayName;
        this.successThreshold = successThreshold;
        this.higherIsBetter = higherIsBetter;
    }

    public String key() {
        return key;
    }

    public String displayName() {
        return displayName;
    }

    public double successThreshold() {
        return successThreshold;
    }

    public boolean higherIsBetter() {
        return higherIsBetter;
    }
}
