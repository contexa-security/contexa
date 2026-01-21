package io.contexa.contexaidentity.security.filter.matcher;

public enum MfaRequestType {

    FACTOR_SELECTION("팩터 선택 처리", true, false),

    CHALLENGE_INITIATION("챌린지 시작", true, false),

    OTT_CODE_REQUEST("OTT 코드 요청", true, false),

    OTT_CODE_VERIFY("OTT 코드 검증", false, false),

    FACTOR_VERIFICATION("팩터 검증", true, false),

    CANCEL_MFA("MFA 취소", true, false),

    LOGIN_PROCESSING("로그인 처리", false, false),

    UNKNOWN("알 수 없는 요청", false, false);

    private final String description;
    private final boolean requiresStateMachineEvent;
    private final boolean allowedInTerminalState;

    MfaRequestType(String description, boolean requiresStateMachineEvent, boolean allowedInTerminalState) {
        this.description = description;
        this.requiresStateMachineEvent = requiresStateMachineEvent;
        this.allowedInTerminalState = allowedInTerminalState;
    }

    public String getDescription() {
        return description;
    }

    public boolean requiresStateMachineEvent() {
        return requiresStateMachineEvent;
    }

    public boolean isAllowedInTerminalState() {
        return allowedInTerminalState;
    }

    public static MfaRequestType fromLegacyType(String legacyType) {
        if (legacyType == null || legacyType.trim().isEmpty()) {
            return UNKNOWN;
        }

        return switch (legacyType.toUpperCase().trim()) {
            case "SELECT_FACTOR" -> FACTOR_SELECTION; 
            case "TOKEN_GENERATION" -> OTT_CODE_REQUEST; 
            case "LOGIN_PROCESSING" -> LOGIN_PROCESSING;
            case "CHALLENGE_REQUEST" -> CHALLENGE_INITIATION; 
            case "VERIFICATION" -> FACTOR_VERIFICATION; 
            case "CANCEL" -> CANCEL_MFA; 
            default -> UNKNOWN;
        };
    }

    @Deprecated(since = "2025-01", forRemoval = true)
    public MfaRequestType toLegacyType() {
        return this; 
    }

    public static MfaRequestType inferFromRequest(String requestUri, String method) {
        if (requestUri == null) return UNKNOWN;

        String uri = requestUri.toLowerCase();

        if (uri.contains("/mfa/select-factor")) {
            return FACTOR_SELECTION;
        }

        if (uri.contains("/mfa/challenge")) {
            return CHALLENGE_INITIATION;
        }

        if (uri.contains("/mfa/verify") || uri.contains("/mfa/submit")) {
            return FACTOR_VERIFICATION;
        }

        if (uri.contains("/mfa/ott/generate") || uri.contains("/mfa/token") || uri.contains("/mfa/otp") || uri.contains("/mfa/sms")) {
            return OTT_CODE_REQUEST;
        }

        if (uri.contains("/login/mfa-ott")) {
            return OTT_CODE_VERIFY;
        }

        if (uri.contains("/mfa/cancel") || uri.contains("/mfa/abort")) {
            return CANCEL_MFA;
        }

        if (uri.contains("/login") || uri.contains("/auth")) {
            return LOGIN_PROCESSING;
        }

        return UNKNOWN;
    }

    public int getPriority() {
        return switch (this) {
            case LOGIN_PROCESSING -> 1;           
            case FACTOR_SELECTION -> 2;
            case CHALLENGE_INITIATION -> 3;
            case FACTOR_VERIFICATION -> 4;
            case OTT_CODE_REQUEST, OTT_CODE_VERIFY -> 5; 
            case CANCEL_MFA -> 6;
            case UNKNOWN -> 7;                   
        };
    }

    public boolean isSafeRequest() {
        return false; 
    }

    public boolean requiresAuthentication() {
        return switch (this) {
            case LOGIN_PROCESSING -> false;       
            case UNKNOWN -> false;                
            default -> true;                      
        };
    }

    public String toDetailedString() {
        return String.format("%s(%s) - StateMachineEvent:%s, TerminalAllowed:%s, Priority:%d",
                name(), description, requiresStateMachineEvent, allowedInTerminalState, getPriority());
    }
}