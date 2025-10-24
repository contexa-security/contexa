package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.client.SimulationClient;
import io.contexa.contexacore.simulation.context.SimulationModeHolder;
import io.contexa.contexacore.simulation.strategy.IAttackStrategy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.HashMap;
import java.util.Map;

/**
 * 공격 전략 기본 클래스
 *
 * 모든 공격 전략이 공통으로 사용하는 기능을 제공합니다.
 * 특히 @Protectable로 보호된 고객 데이터 엔드포인트 호출 기능을 제공합니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
public abstract class BaseAttackStrategy implements IAttackStrategy {

    @Autowired(required = false)
    protected SimulationClient simulationClient;

    /**
     * @Protectable로 보호된 고객 데이터 엔드포인트 호출
     *
     * 이 메서드는 각 공격 패턴이 최종적으로 고객 데이터에 접근을 시도할 때 사용됩니다.
     * 시뮬레이션 모드에 따라:
     * - 무방비 모드: 헤더에 UNPROTECTED 설정, 보안 우회
     * - 방어 모드: 헤더에 PROTECTED 설정, 보안 체크
     *
     * @param customerId 접근할 고객 ID
     * @param attackType 공격 유형
     * @param context 공격 컨텍스트
     * @return 접근 성공 여부
     */
    protected boolean attemptCustomerDataAccess(String customerId, String attackType,
                                               AttackContext context) {
        try {
            // SimulationClient null 체크
            if (simulationClient == null) {
                log.error("SimulationClient is not initialized. Cannot access protected endpoint for customer: {}", customerId);
                return false;
            }

            // 시뮬레이션 컨텍스트 확인
            SimulationModeHolder.SimulationContext simContext = SimulationModeHolder.getContext();

            // HTTP 헤더 구성
            Map<String, String> headers = new HashMap<>();

            // 시뮬레이션 모드 헤더 설정
            if (simContext != null) {
                headers.put("X-Simulation-Mode", simContext.getMode().toString());
                headers.put("X-Simulation-Campaign", simContext.getCampaignId());
                headers.put("X-Simulation-Attack", simContext.getAttackId());
            } else {
                // 컨텍스트가 없을 경우 기본값 설정
                log.warn("No simulation context found. Using default UNPROTECTED mode.");
                headers.put("X-Simulation-Mode", "UNPROTECTED");
            }

            // 공격 정보 헤더
            headers.put("X-Attack-Type", attackType);
            headers.put("X-Attack-Id", context.getAttackId());
            headers.put("X-Source-IP", context.getSourceIp());
            headers.put("User-Agent", context.getUserAgent());

            // @Protectable로 보호된 엔드포인트 호출
            String endpoint = "/api/protected/customer/" + customerId;

            log.info("Attempting to access protected endpoint: {} with mode: {}",
                    endpoint, simContext != null ? simContext.getMode() : "NORMAL");

            // SimulationClient를 통해 HTTP 요청 전송
            Map<String, String> params = new HashMap<>();
            ResponseEntity<String> response = simulationClient.get(endpoint, params, headers);

            // 응답 처리
            if (response.getStatusCode() == HttpStatus.OK) {
                // 데이터 접근 성공 (무방비 모드 또는 방어 실패)
                log.warn("Customer data accessed - Attack: {}, Customer: {}, Mode: {}",
                        attackType, customerId,
                        simContext != null ? simContext.getMode() : "NORMAL");
                return true;

            } else if (response.getStatusCode() == HttpStatus.FORBIDDEN) {
                // 보안 시스템에 의해 차단됨 (방어 모드)
                log.info("Access blocked by security - Attack: {}, Customer: {}",
                        attackType, customerId);
                return false;

            } else {
                log.debug("Unexpected response: {}", response.getStatusCode());
                return false;
            }

        } catch (Exception e) {
            log.error("Error accessing protected endpoint for customer: {}", customerId, e);
            return false;
        }
    }

    /**
     * 여러 고객에 대한 대량 접근 시도
     *
     * @param customerIds 고객 ID 배열
     * @param attackType 공격 유형
     * @param context 공격 컨텍스트
     * @return 성공한 접근 수
     */
    protected int attemptBulkCustomerDataAccess(String[] customerIds, String attackType,
                                               AttackContext context) {
        int successCount = 0;

        for (String customerId : customerIds) {
            if (attemptCustomerDataAccess(customerId, attackType, context)) {
                successCount++;
            }
        }

        log.info("Bulk access attempt - Total: {}, Success: {}, Blocked: {}",
                customerIds.length, successCount, customerIds.length - successCount);

        return successCount;
    }

    /**
     * 공격 결과 빌더 헬퍼
     *
     * @param context 공격 컨텍스트
     * @param success 성공 여부
     * @param breachedCount 유출된 레코드 수
     * @return 공격 결과
     */
    protected AttackResult buildResult(AttackContext context, boolean success, int breachedCount) {
        AttackResult result = AttackResult.builder()
                .attackId(context.getAttackId())
                .campaignId(context.getCampaignId())
                .attackType(getType())
                .targetUser(context.getTargetUser())
                .sourceIp(context.getSourceIp())
                .successful(success)
                .dataBreached(breachedCount > 0)
                .breachedRecordCount(breachedCount)
                .build();

        // 시뮬레이션 모드 정보 추가
        SimulationModeHolder.SimulationContext simContext = SimulationModeHolder.getContext();
        if (simContext != null) {
            result.getDetails().put("simulationMode", simContext.getMode().toString());
            result.getDetails().put("bypassedSecurity", simContext.shouldBypassSecurity());
        }

        return result;
    }

    /**
     * 고객 ID 생성 헬퍼
     *
     * @param prefix 프리픽스
     * @param count 생성할 개수
     * @return 고객 ID 배열
     */
    protected String[] generateCustomerIds(String prefix, int count) {
        String[] ids = new String[count];
        for (int i = 0; i < count; i++) {
            ids[i] = prefix + "-" + (i + 1);
        }
        return ids;
    }
}