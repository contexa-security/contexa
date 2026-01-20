package io.contexa.contexacommon.hcad.domain;


public enum BaselineMatchStatus {

    
    MATCH("MATCH", "All criteria matched"),

    
    PARTIAL("PARTIAL", "Same browser and OS, version differs (normal auto-update)"),

    
    MISMATCH("MISMATCH", "Criteria mismatch, possible account takeover"),

    
    UNKNOWN("UNKNOWN", "Cannot compare, data unavailable");

    private final String code;
    private final String description;

    BaselineMatchStatus(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }

    
    public static BaselineMatchStatus fromString(String status) {
        if (status == null) {
            return UNKNOWN;
        }
        for (BaselineMatchStatus s : values()) {
            if (s.code.equalsIgnoreCase(status)) {
                return s;
            }
        }
        return UNKNOWN;
    }

    
    @Override
    public String toString() {
        return code;
    }
}
