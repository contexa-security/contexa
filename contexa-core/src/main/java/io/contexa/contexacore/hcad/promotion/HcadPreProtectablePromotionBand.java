package io.contexa.contexacore.hcad.promotion;

public enum HcadPreProtectablePromotionBand {
    LOW,
    MEDIUM,
    HIGH,
    REDLINE;

    public String serializedValue() {
        return name();
    }
}