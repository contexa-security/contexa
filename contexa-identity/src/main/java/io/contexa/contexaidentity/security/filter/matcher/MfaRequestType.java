package io.contexa.contexaidentity.security.filter.matcher;

/**
 * 완전 일원화된 MFA 요청 타입
 * - 모든 MFA 요청 타입을 통합 관리
 * - State Machine 기반 처리를 위한 명확한 분류
 * - 레거시 호환성 및 신규 기능 모두 지원
 */
public enum MfaRequestType {

    // === 팩터 선택 관련 ===
    /**
     * 팩터 선택 처리
     * - 사용자가 선택한 팩터 처리
     * - Event: FACTOR_SELECTED
     * - GET: 팩터 선택 UI 페이지, POST: 팩터 선택 API 처리
     */
    FACTOR_SELECTION("팩터 선택 처리", true, false),

    // === 챌린지 관련 ===
    /**
     * 챌린지 시작
     * - 선택된 팩터에 대한 챌린지 프로세스 시작
     * - Event: INITIATE_CHALLENGE
     */
    CHALLENGE_INITIATION("챌린지 시작", true, false),

    // === OTT 전용 타입 ===
    /**
     * OTT 코드 요청 (신규)
     * - OTT 코드 생성 및 이메일 전송 요청
     * - Event: INITIATE_CHALLENGE
     * - URL: POST /mfa/ott/generate-code
     */
    OTT_CODE_REQUEST("OTT 코드 요청", true, false),

    /**
     * OTT 코드 검증 (신규)
     * - 사용자가 입력한 OTT 코드 검증
     * - FilterChain으로 위임하여 OttAuthenticationFilter에서 처리
     * - URL: POST /login/mfa-ott
     */
    OTT_CODE_VERIFY("OTT 코드 검증", false, false),

    // === 검증 관련 ===
    /**
     * 팩터 검증
     * - 제출된 팩터 자격증명 검증
     * - Event: SUBMIT_FACTOR_CREDENTIAL
     */
    FACTOR_VERIFICATION("팩터 검증", true, false),

    // === 제어 관련 ===
    /**
     * MFA 취소
     * - 사용자에 의한 MFA 프로세스 취소
     * - Event: USER_ABORTED_MFA
     */
    CANCEL_MFA("MFA 취소", true, false),

    // === 인증 관련 ===
    /**
     * 로그인 처리
     * - 실제 인증 처리는 다른 필터로 위임
     * - FilterChain 계속 진행
     */
    LOGIN_PROCESSING("로그인 처리", false, false),

    // === 기타 ===
    /**
     * 알 수 없는 요청
     * - 매칭되지 않는 요청 타입
     * - 오류 응답 반환
     */
    UNKNOWN("알 수 없는 요청", false, false);

    private final String description;
    private final boolean requiresStateMachineEvent;
    private final boolean allowedInTerminalState;

    MfaRequestType(String description, boolean requiresStateMachineEvent, boolean allowedInTerminalState) {
        this.description = description;
        this.requiresStateMachineEvent = requiresStateMachineEvent;
        this.allowedInTerminalState = allowedInTerminalState;
    }

    /**
     * 요청 타입 설명 조회
     */
    public String getDescription() {
        return description;
    }

    /**
     * State Machine 이벤트 필요 여부 확인
     * @return true: State Machine 이벤트가 필요한 요청
     */
    public boolean requiresStateMachineEvent() {
        return requiresStateMachineEvent;
    }

    /**
     * 터미널 상태에서 허용되는 요청인지 확인
     * @return true: 터미널 상태에서도 처리 가능한 요청
     */
    public boolean isAllowedInTerminalState() {
        return allowedInTerminalState;
    }

    /**
     * 레거시 타입을 통합 타입으로 변환
     * @param legacyType 레거시 타입 문자열
     * @return 변환된 MfaRequestType
     */
    public static MfaRequestType fromLegacyType(String legacyType) {
        if (legacyType == null || legacyType.trim().isEmpty()) {
            return UNKNOWN;
        }

        return switch (legacyType.toUpperCase().trim()) {
            case "SELECT_FACTOR" -> FACTOR_SELECTION; // 레거시 호환: SELECT_FACTOR → FACTOR_SELECTION
            case "TOKEN_GENERATION" -> OTT_CODE_REQUEST; // 레거시 호환: TOKEN_GENERATION → OTT_CODE_REQUEST
            case "LOGIN_PROCESSING" -> LOGIN_PROCESSING;
            case "CHALLENGE_REQUEST" -> CHALLENGE_INITIATION; // 레거시 호환: CHALLENGE_REQUEST → CHALLENGE_INITIATION
            case "VERIFICATION" -> FACTOR_VERIFICATION; // 레거시 호환: VERIFICATION → FACTOR_VERIFICATION
            case "CANCEL" -> CANCEL_MFA; // 레거시 호환: CANCEL → CANCEL_MFA
            default -> UNKNOWN;
        };
    }

    /**
     * 레거시 타입으로 변환 (하위 호환성)
     * @deprecated 레거시 타입이 제거되어 더 이상 필요하지 않음. 모든 타입이 직접 사용됨.
     * @return 자기 자신 반환
     */
    @Deprecated(since = "2025-01", forRemoval = true)
    public MfaRequestType toLegacyType() {
        return this; // 레거시 타입 제거로 인해 모든 타입이 직접 사용됨
    }

    /**
     * URL 패턴 기반 요청 타입 추론
     * @param requestUri 요청 URI
     * @param method HTTP 메서드
     * @return 추론된 MfaRequestType
     */
    public static MfaRequestType inferFromRequest(String requestUri, String method) {
        if (requestUri == null) return UNKNOWN;

        String uri = requestUri.toLowerCase();

        // 팩터 선택
        if (uri.contains("/mfa/select-factor")) {
            return FACTOR_SELECTION;
        }

        // 챌린지
        if (uri.contains("/mfa/challenge")) {
            return CHALLENGE_INITIATION;
        }

        // 검증
        if (uri.contains("/mfa/verify") || uri.contains("/mfa/submit")) {
            return FACTOR_VERIFICATION;
        }

        // OTT 코드 생성
        if (uri.contains("/mfa/ott/generate") || uri.contains("/mfa/token") || uri.contains("/mfa/otp") || uri.contains("/mfa/sms")) {
            return OTT_CODE_REQUEST;
        }

        // OTT 코드 검증
        if (uri.contains("/login/mfa-ott")) {
            return OTT_CODE_VERIFY;
        }

        // 취소
        if (uri.contains("/mfa/cancel") || uri.contains("/mfa/abort")) {
            return CANCEL_MFA;
        }

        // 로그인
        if (uri.contains("/login") || uri.contains("/auth")) {
            return LOGIN_PROCESSING;
        }

        return UNKNOWN;
    }

    /**
     * 요청 타입의 우선순위 반환
     * @return 우선순위 (낮을수록 높은 우선순위)
     */
    public int getPriority() {
        return switch (this) {
            case LOGIN_PROCESSING -> 1;           // 최고 우선순위
            case FACTOR_SELECTION -> 2;
            case CHALLENGE_INITIATION -> 3;
            case FACTOR_VERIFICATION -> 4;
            case OTT_CODE_REQUEST, OTT_CODE_VERIFY -> 5; // OTT 전용 타입
            case CANCEL_MFA -> 6;
            case UNKNOWN -> 7;                   // 최저 우선순위
        };
    }

    /**
     * 요청 타입이 안전한지 확인 (CSRF 등)
     * @return true: 안전한 요청 (GET 등), false: 위험한 요청 (POST 등)
     */
    public boolean isSafeRequest() {
        return false; // 모든 MFA 요청은 POST로 간주
    }

    /**
     * 인증이 필요한 요청인지 확인
     * @return true: 인증 필요, false: 인증 불필요
     */
    public boolean requiresAuthentication() {
        return switch (this) {
            case LOGIN_PROCESSING -> false;       // 로그인 과정에서는 인증이 아직 완료되지 않음
            case UNKNOWN -> false;                // 알 수 없는 요청은 다른 곳에서 처리
            default -> true;                      // 나머지는 모두 인증 필요
        };
    }

    /**
     * 로깅용 상세 정보 반환
     * @return 로깅에 적합한 상세 정보
     */
    public String toDetailedString() {
        return String.format("%s(%s) - StateMachineEvent:%s, TerminalAllowed:%s, Priority:%d",
                name(), description, requiresStateMachineEvent, allowedInTerminalState, getPriority());
    }
}