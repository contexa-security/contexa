package io.contexa.contexacore.autonomous.event.domain;

/**
 * Zero Trust 이벤트 카테고리 (핸들러 라우팅용)
 *
 * AI Native v13.0: 이벤트 기반 Zero Trust 아키텍처
 *
 * 설계 원칙:
 * - 카테고리는 고정적이며 변경이 거의 없음
 * - 핸들러 라우팅의 기준점 역할
 * - CUSTOM 카테고리로 완전히 새로운 이벤트 유형도 처리 가능
 *
 * 확장성:
 * - 새 이벤트 타입은 eventType(문자열)로 무제한 확장
 * - 카테고리 추가는 거의 발생하지 않음
 *
 * @author contexa
 * @since 4.0.0
 */
public enum ZeroTrustEventCategory {

    /**
     * 인증 관련 이벤트
     * - 로그인 성공/실패
     * - MFA 인증
     * - 토큰 발급/갱신
     */
    AUTHENTICATION,

    /**
     * 인가 관련 이벤트
     * - Web 요청 인가 결정
     * - Method 수준 인가 결정
     * - 리소스 접근 제어
     */
    AUTHORIZATION,

    /**
     * 세션 관련 이벤트
     * - 세션 생성/만료
     * - 세션 속성 변경
     * - 동시 세션 제어
     */
    SESSION,

    /**
     * 위협 탐지 이벤트
     * - 이상 행위 탐지
     * - 공격 시도 탐지
     * - 정책 위반 탐지
     */
    THREAT,

    /**
     * 확장용 - 애플리케이션 정의 이벤트
     *
     * 사용 예시:
     * - PAYMENT_FRAUD_DETECTED
     * - DATA_EXPORT_REQUEST
     * - SENSITIVE_OPERATION
     *
     * 플러그 앤 플레이:
     * - 애플리케이션에서 자유롭게 이벤트 타입 정의
     * - 공통 모듈 코드 변경 없이 바로 사용
     */
    CUSTOM
}
