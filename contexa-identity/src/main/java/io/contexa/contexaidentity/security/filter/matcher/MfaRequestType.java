package io.contexa.contexaidentity.security.filter.matcher;

/**
 * 완전 일원화된 MFA 요청 타입
 * - 모든 MFA 요청 타입을 통합 관리
 * - State Machine 기반 처리를 위한 명확한 분류
 * - 레거시 호환성 및 신규 기능 모두 지원
 */
public enum MfaRequestType {

    // === 초기화 관련 ===
    /**
     * MFA 프로세스 시작 요청
     * - 1차 인증 완료 후 MFA 프로세스 개시
     * - State: PRIMARY_AUTHENTICATION_COMPLETED -> AWAITING_FACTOR_SELECTION
     */
    MFA_INITIATE("MFA 프로세스 시작", true, false),

    // === 팩터 선택 관련 ===
    /**
     * 팩터 선택 페이지 요청 (레거시)
     * - 팩터 선택 UI 렌더링 요청
     */
    SELECT_FACTOR("팩터 선택 페이지 요청", false, false),

    /**
     * 팩터 선택 처리 (신규)
     * - 사용자가 선택한 팩터 처리
     * - Event: FACTOR_SELECTED
     */
    FACTOR_SELECTION("팩터 선택 처리", true, false),

    // === 챌린지 관련 ===
    /**
     * 챌린지 시작 (신규)
     * - 선택된 팩터에 대한 챌린지 프로세스 시작
     * - Event: INITIATE_CHALLENGE
     */
    CHALLENGE_INITIATION("챌린지 시작", true, false),

    /**
     * 챌린지 요청 (레거시)
     * - 챌린지 데이터 요청
     */
    CHALLENGE_REQUEST("챌린지 요청", false, false),

    /**
     * 토큰 생성 (레거시 - OTT 등)
     * - OTP, SMS 등의 토큰 생성 요청
     */
    TOKEN_GENERATION("토큰 생성 (OTT 등)", false, false),

    // === 검증 관련 ===
    /**
     * 팩터 검증 (신규)
     * - 제출된 팩터 자격증명 검증
     * - Event: SUBMIT_FACTOR_CREDENTIAL
     */
    FACTOR_VERIFICATION("팩터 검증", true, false),

    /**
     * 검증 처리 (레거시)
     * - 일반적인 검증 요청
     */
    VERIFICATION("검증 처리", false, false),

    // === 상태 관리 ===
    /**
     * 상태 확인 (신규)
     * - 현재 MFA 진행 상태 조회
     * - 터미널 상태에서도 허용
     */
    STATUS_CHECK("상태 확인", false, true),

    /**
     * 세션 갱신 (신규)
     * - MFA 세션 유효 시간 연장
     * - 터미널 상태에서도 허용
     */
    SESSION_REFRESH("세션 갱신", false, true),

    // === 제어 관련 ===
    /**
     * MFA 취소 (신규)
     * - 사용자에 의한 MFA 프로세스 취소
     * - Event: USER_ABORTED_MFA
     */
    CANCEL_MFA("MFA 취소", true, false),

    /**
     * 취소 처리 (레거시)
     * - 일반적인 취소 요청
     */
    CANCEL("취소 처리", false, false),

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
            case "MFA_INITIATE" -> MFA_INITIATE;
            case "SELECT_FACTOR" -> SELECT_FACTOR;
            case "TOKEN_GENERATION" -> TOKEN_GENERATION;
            case "LOGIN_PROCESSING" -> LOGIN_PROCESSING;
            case "CHALLENGE_REQUEST" -> CHALLENGE_REQUEST;
            case "VERIFICATION" -> VERIFICATION;
            case "CANCEL" -> CANCEL;
            default -> UNKNOWN;
        };
    }

    /**
     * 신규 타입을 레거시 타입으로 변환 (하위 호환성)
     * @return 레거시 호환 타입
     */
    public MfaRequestType toLegacyType() {
        return switch (this) {
            case FACTOR_SELECTION -> SELECT_FACTOR;
            case CHALLENGE_INITIATION -> MFA_INITIATE;
            case FACTOR_VERIFICATION -> TOKEN_GENERATION;
            case CANCEL_MFA -> CANCEL;
            case STATUS_CHECK, SESSION_REFRESH -> UNKNOWN; // 레거시에서 지원하지 않음
            default -> this;
        };
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
        String httpMethod = method != null ? method.toUpperCase() : "GET";

        // MFA 시작
        if (uri.contains("/mfa/initiate") || uri.contains("/mfa/start")) {
            return MFA_INITIATE;
        }

        // 팩터 선택
        if (uri.contains("/mfa/select-factor")) {
            return "POST".equals(httpMethod) ? FACTOR_SELECTION : SELECT_FACTOR;
        }

        // 챌린지
        if (uri.contains("/mfa/challenge")) {
            return "POST".equals(httpMethod) ? CHALLENGE_INITIATION : CHALLENGE_REQUEST;
        }

        // 검증
        if (uri.contains("/mfa/verify") || uri.contains("/mfa/submit")) {
            return FACTOR_VERIFICATION;
        }

        // 토큰 생성 (OTT)
        if (uri.contains("/mfa/token") || uri.contains("/mfa/otp") || uri.contains("/mfa/sms")) {
            return TOKEN_GENERATION;
        }

        // 상태 관리
        if (uri.contains("/mfa/status")) {
            return STATUS_CHECK;
        }

        if (uri.contains("/mfa/refresh")) {
            return SESSION_REFRESH;
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
            case MFA_INITIATE -> 2;
            case FACTOR_SELECTION, SELECT_FACTOR -> 3;
            case CHALLENGE_INITIATION, CHALLENGE_REQUEST -> 4;
            case FACTOR_VERIFICATION, VERIFICATION -> 5;
            case TOKEN_GENERATION -> 6;
            case STATUS_CHECK -> 7;
            case SESSION_REFRESH -> 8;
            case CANCEL_MFA, CANCEL -> 9;
            case UNKNOWN -> 10;                   // 최저 우선순위
        };
    }

    /**
     * 요청 타입이 안전한지 확인 (CSRF 등)
     * @return true: 안전한 요청 (GET 등), false: 위험한 요청 (POST 등)
     */
    public boolean isSafeRequest() {
        return switch (this) {
            case STATUS_CHECK, SELECT_FACTOR, CHALLENGE_REQUEST -> true;
            default -> false;
        };
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