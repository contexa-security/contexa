package io.contexa.contexacommon.annotation;

/**
 * @Protectable 리소스의 LLM 분석 요구 수준
 *
 * 민감도에 따라 분석 완료 여부를 다르게 처리하여
 * Zero Trust 원칙과 사용성 사이의 균형을 제공한다.
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
public enum AnalysisRequirement {

    /**
     * 분석 없어도 통과 가능
     *
     * 용도: 공개 API, 읽기 전용 리소스
     * 동작: LLM 분석 결과와 무관하게 접근 허용
     * 예시: 공개 정보 조회, 헬스체크 API
     */
    NOT_REQUIRED,

    /**
     * 분석 있으면 좋지만 없어도 통과 (기본값)
     *
     * 용도: 일반 리소스, 로그인 후 기본 접근
     * 동작:
     *   - 분석 완료: action 기반 판단
     *   - 분석 미완료: defaultAction 사용하여 처리
     * 예시: 일반 조회, 목록 API
     */
    PREFERRED,

    /**
     * 분석 완료 필수 (동기 대기)
     *
     * 용도: 민감 데이터 접근, 상태 변경 API
     * 동작:
     *   - 분석 완료: action 기반 판단
     *   - 분석 미완료: analysisTimeout까지 대기 후 거부
     * 예시: 개인정보 조회, 결제 처리
     */
    REQUIRED,

    /**
     * 분석 완료 + 특정 action(ALLOW) 필수
     *
     * 용도: 관리자 기능, 금융 거래, PII 접근
     * 동작:
     *   - 분석 완료 + ALLOW: 접근 허용
     *   - 분석 완료 + 기타 action: 거부
     *   - 분석 미완료: analysisTimeout까지 대기 후 거부
     * 예시: 사용자 삭제, 대량 데이터 다운로드, 권한 변경
     */
    STRICT
}
