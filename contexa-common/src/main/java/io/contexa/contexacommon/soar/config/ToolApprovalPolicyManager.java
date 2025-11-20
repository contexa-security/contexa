package io.contexa.contexacommon.soar.config;

import io.contexa.contexacommon.annotation.SoarTool;

/**
 * Tool Approval Policy Manager Interface
 *
 * <p>
 * Core와 Enterprise 사이의 SOAR 도구 승인 정책 관리 인터페이스입니다.
 * Enterprise가 있으면 실제 정책이 적용되고, 없으면 기본 동작.
 * </p>
 *
 * @since 0.1.1
 */
public interface ToolApprovalPolicyManager {

    /**
     * 도구의 위험도 수준 조회
     *
     * @param toolName 도구 이름
     * @return 위험도 수준
     */
    SoarTool.RiskLevel getRiskLevel(String toolName);

    /**
     * 도구가 차단되었는지 확인
     *
     * @param toolName 도구 이름
     * @return 차단 여부
     */
    boolean isBlocked(String toolName);

    /**
     * 도구가 승인이 필요한지 확인
     *
     * @param toolName 도구 이름
     * @return 승인 필요 여부
     */
    boolean requiresApproval(String toolName);

    /**
     * 승인 타임아웃 조회
     *
     * @param toolName 도구 이름
     * @return 타임아웃 (초)
     */
    int getApprovalTimeout(String toolName);
}
