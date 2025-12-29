package io.contexa.contexacore.autonomous.domain;

import lombok.Builder;
import lombok.Getter;
import java.time.Instant;

/**
 * 관리자 개입 도메인 클래스 (AI Native v3.4.0)
 *
 * AI Native 원칙:
 * - BLOCK 판정된 요청에 대해 관리자가 검토 후 승인/거부 결정
 * - 승인 시 기준선 업데이트 허용 여부를 별도로 결정
 * - 모든 관리자 개입은 감사 로그로 영구 기록
 *
 * 기준선 오염 방지 메커니즘:
 * - 관리자가 명시적으로 baselineUpdateAllowed=true로 설정해야만 학습
 * - 단순 ALLOW 전환만으로는 기준선 업데이트되지 않음
 * - 이는 "이 요청이 향후 정상 패턴으로 학습되어도 좋다"는 명시적 승인
 *
 * 사용 시나리오:
 * 1. LLM이 BLOCK 판정
 * 2. 관리자가 검토하여 오탐으로 판단
 * 3. 관리자가 ALLOW로 전환 + baselineUpdateAllowed=true 설정
 * 4. 해당 패턴이 사용자 기준선에 학습됨
 *
 * Redis 저장 스키마:
 * - Key: security:admin:override:{requestId}
 * - TTL: 30일 (감사 목적)
 * - 인덱스: security:admin:override:user:{userId}
 *
 * @author contexa
 * @since 3.4.0
 */
@Getter
@Builder
public class AdminOverride {

    /** 고유 ID (UUID) */
    private final String overrideId;

    /** 원본 요청 ID (분석 결과와 매핑) */
    private final String requestId;

    /** 대상 사용자 ID */
    private final String userId;

    /** 관리자 ID (개입 수행자) */
    private final String adminId;

    /** 개입 시간 */
    private final Instant timestamp;

    /** 원래 LLM 판정 (BLOCK/CHALLENGE/ESCALATE) */
    private final String originalAction;

    /** 전환된 Action (ALLOW/CHALLENGE) */
    private final String overriddenAction;

    /** 관리자 개입 사유 (필수 - 감사 로그용) */
    private final String reason;

    /** 승인 여부 (true=승인하여 Action 전환, false=거부하여 원래 Action 유지) */
    private final boolean approved;

    /**
     * 기준선 업데이트 허용 여부
     *
     * true: 이 요청 패턴을 사용자의 정상 기준선에 학습
     * false: Action만 전환하고 기준선은 업데이트하지 않음
     *
     * 기준선 오염 방지:
     * - 승인(approved=true)과 별도로 명시적 허용 필요
     * - 일회성 예외 허용 시 false로 설정
     * - 패턴을 정상으로 학습시키려면 true로 설정
     */
    private final boolean baselineUpdateAllowed;

    /** 원래 LLM riskScore (감사 로그용) */
    private final double originalRiskScore;

    /** 원래 LLM confidence (감사 로그용) */
    private final double originalConfidence;

    /**
     * 기준선 업데이트 가능 여부 판단
     *
     * 조건:
     * 1. 승인됨 (approved = true)
     * 2. 기준선 업데이트 허용됨 (baselineUpdateAllowed = true)
     * 3. 전환된 Action이 ALLOW (overriddenAction = ALLOW)
     *
     * AI Native 원칙:
     * - 세 조건 모두 충족해야만 기준선에 학습
     * - 하나라도 미충족 시 기준선 보호
     *
     * @return 기준선 업데이트 가능하면 true
     */
    public boolean canUpdateBaseline() {
        return approved
            && baselineUpdateAllowed
            && "ALLOW".equalsIgnoreCase(overriddenAction);
    }

    /**
     * 승인 여부와 무관하게 기준선 업데이트가 허용되었는지 확인
     *
     * @return 기준선 업데이트 허용 플래그
     */
    public boolean isBaselineUpdateAllowed() {
        return baselineUpdateAllowed;
    }

    /**
     * 로그 출력용 toString
     */
    @Override
    public String toString() {
        return String.format(
            "AdminOverride{overrideId='%s', requestId='%s', userId='%s', adminId='%s', " +
            "originalAction='%s', overriddenAction='%s', approved=%s, baselineUpdateAllowed=%s}",
            overrideId, requestId, userId, adminId,
            originalAction, overriddenAction, approved, baselineUpdateAllowed
        );
    }
}
