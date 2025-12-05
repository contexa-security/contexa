package io.contexa.contexacommon.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * [재설계 - Zero Trust 보안 아키텍처]
 *
 * 동적 인가 정책의 대상이 되는 서비스 계층의 메서드를 명시적으로 지정하고,
 * 해당 메서드에 필요한 '비즈니스 권한 이름'을 선언합니다.
 * MethodResourceScanner는 이 어노테이션이 붙은 메서드만 스캔합니다.
 *
 * Phase 5 확장 (Zero Trust):
 * - analysisRequirement: LLM 분석 요구 수준
 * - analysisTimeout: 분석 대기 타임아웃
 * - defaultAction: 분석 미완료 시 기본 action
 * - enableRuntimeInterception: 실시간 응답 차단 활성화
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Protectable {

    /**
     * 소유자 확인을 위한 엔티티 필드명
     * 예: "ownerId", "createdBy", "userId"
     * 이 필드가 지정되면 해당 객체의 소유자 확인이 자동으로 수행됩니다.
     *
     * @return 소유자 필드명
     */
    String ownerField() default "";

    // Note: condition 표현식은 policy_condition 테이블에서 관리됨
    // SpEL 예: "#trust.levelExceeds(0.5)" 또는 "#ai.isAllowed() and hasRole('ADMIN')"

    /**
     * LLM 분석 요구 수준
     *
     * - NOT_REQUIRED: 분석 없어도 통과
     * - PREFERRED: 분석 있으면 사용, 없어도 통과 (기본값)
     * - REQUIRED: 분석 완료까지 대기 (동기)
     * - STRICT: 분석 완료 + ALLOW action 필수
     *
     * @return 분석 요구 수준
     */
    AnalysisRequirement analysisRequirement() default AnalysisRequirement.PREFERRED;

    /**
     * 분석 대기 타임아웃 (밀리초)
     *
     * analysisRequirement가 REQUIRED 또는 STRICT일 때만 적용
     * 기본값: 5000ms (5초)
     * 최대값: 30000ms (30초)
     *
     * @return 타임아웃 밀리초
     */
    long analysisTimeout() default 5000;

    /**
     * 분석 미완료 시 기본 action
     *
     * analysisRequirement가 NOT_REQUIRED 또는 PREFERRED일 때 사용
     * 가능한 값: ALLOW, MONITOR, BLOCK, CHALLENGE
     * 기본값: MONITOR (모니터링 모드로 접근 허용)
     *
     * @return 기본 action 문자열
     */
    String defaultAction() default "MONITOR";

    /**
     * 실시간 응답 차단 활성화 (Phase 7)
     *
     * true: LLM 분석 완료 시 응답이 아직 커밋되지 않았으면 차단 시도
     * false: 실시간 차단 비활성화 (기본값)
     *
     * 권장 사용:
     * - 대량 데이터 조회 API
     * - 파일 다운로드 API
     * - 스트리밍 응답 API
     *
     * @return 실시간 차단 활성화 여부
     */
    boolean enableRuntimeInterception() default false;
}