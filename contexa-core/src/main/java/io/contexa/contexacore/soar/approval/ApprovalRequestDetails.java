package io.contexa.contexacore.soar.approval;

import java.io.Serializable;
import java.util.Map;

/**
 * SOAR 승인 요청 상세 정보
 *
 * <p>
 * 승인 요청 시 필요한 상세 정보를 담는 데이터 전송 객체입니다.
 * </p>
 *
 * @since 0.1.1
 */
public record ApprovalRequestDetails(
        String actionName,
        String actionType,
        String riskLevel,
        String description,
        String arguments,
        Map<String, Object> parameters) implements Serializable {}
