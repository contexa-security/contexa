package io.contexa.contexacommon.enums;


public enum AuthType {
    FORM(false),
    REST(false),

    
    PASSKEY(false),      
    OTT(true),           
    RECOVERY_CODE(true), 

    
    MFA(false),
    MFA_FORM(false),
    MFA_REST(false),
    MFA_OTT(false),
    MFA_PASSKEY(false),
    PRIMARY(false);

    
    private final boolean allowChallengeReuse;

    AuthType(boolean allowChallengeReuse) {
        this.allowChallengeReuse = allowChallengeReuse;
    }

    
    public boolean isAllowChallengeReuse() {
        return allowChallengeReuse;
    }
}
