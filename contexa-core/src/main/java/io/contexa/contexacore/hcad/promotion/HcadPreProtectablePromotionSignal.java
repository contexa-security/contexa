package io.contexa.contexacore.hcad.promotion;

public enum HcadPreProtectablePromotionSignal {
    IMPOSSIBLE_TRAVEL(true, 45),
    NEW_DEVICE(true, 25),
    FAILED_LOGIN_BURST(true, 30),
    AUTH_CONTEXT_INCONSISTENT(true, 40),
    REQUEST_BURST(false, 10),
    RAPID_SEQUENCE(false, 10),
    PREVIOUS_PATH_JUMP(false, 10),
    SENSITIVE_SURFACE(false, 20),
    BASELINE_UNCERTAIN(false, 5);

    private final boolean anchor;
    private final int weight;

    HcadPreProtectablePromotionSignal(boolean anchor, int weight) {
        this.anchor = anchor;
        this.weight = weight;
    }

    public boolean isAnchor() {
        return anchor;
    }

    public int weight() {
        return weight;
    }
}