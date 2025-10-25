package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.domain.entity.CustomerData;
import io.contexa.contexaiam.aiam.service.ProtectableDataService;
import io.contexa.contexacore.simulation.context.SimulationModeHolder;
import io.contexa.contexacore.simulation.tracker.DataBreachTracker;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;

/**
 * 보호된 고객 데이터 접근 컨트롤러
 *
 * 이 컨트롤러는 @Protectable 어노테이션으로 보호되는 통합 엔드포인트를 제공합니다.
 * 시뮬레이션 모드에 따라:
 * - 무방비 모드: SimulationModeHolder가 UNPROTECTED로 설정되면 보안 우회
 * - 방어 모드: SimulationModeHolder가 PROTECTED로 설정되면 정상적인 보안 체크
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("/api/protected")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class ProtectedCustomerDataController {

    private final ProtectableDataService protectableDataService;
    private final DataBreachTracker dataBreachTracker;

    /**
     * 통합 고객 데이터 접근 엔드포인트
     *
     * 모든 공격 패턴이 이 단일 엔드포인트를 통해 고객 데이터에 접근을 시도합니다.
     * @Protectable 어노테이션이 적용되어 있어 자율보안체제의 보호를 받습니다.
     *
     * @param customerId 조회할 고객 ID
     * @param attackType 공격 유형 (선택사항, 로깅용)
     * @return 고객 데이터 또는 접근 거부
     */
    @GetMapping("/customer/{customerId}")
    public ResponseEntity<?> getCustomerData(
            @PathVariable String customerId,
            @RequestParam(required = false) String attackType,
            @RequestHeader(value = "X-Attack-Type", required = false) String attackHeader,
            @RequestHeader(value = "X-Simulation-Mode", required = false) String simulationMode) {

        // 시뮬레이션 컨텍스트 확인
        SimulationModeHolder.SimulationContext context = SimulationModeHolder.getContext();
        String actualAttackType = attackType != null ? attackType : attackHeader;

        log.info("Customer data access attempt - ID: {}, Attack: {}, Mode: {}, Context: {}",
                customerId, actualAttackType, simulationMode,
                context != null ? context.getMode() : "NORMAL");

        try {
            // 시뮬레이션 모드에서는 자율보안운영체제가 백그라운드에서 위협 평가를 완료할 시간 제공
          /*  if (context != null && context.isSimulation()) {
                log.debug("Waiting for autonomous security system to complete threat assessment...");
                Thread.sleep(2500); // 2.5초 대기
            }*/

            // CustomerDataService의 @Protectable 메서드 호출
            // 이 호출은 CustomDynamicAuthorizationManager를 거칩니다
            Optional<CustomerData> customerDataOpt = protectableDataService.getCustomerData(customerId);

            if (customerDataOpt.isPresent()) {
                CustomerData data = customerDataOpt.get();

                // 데이터 접근 성공 (보안 체크 통과 또는 우회)
                log.warn("Customer data accessed successfully - ID: {}, Sensitivity: {}",
                        customerId, data.getSensitivityLevel());

                // 시뮬레이션 컨텍스트가 있으면 DataBreachTracker에 기록
                if (context != null && context.isSimulation()) {
                    dataBreachTracker.recordDataBreach(
                        context.getCampaignId(),
                        context.getAttackId(),
                        actualAttackType != null ? actualAttackType : "UNKNOWN",
                        data,
                        context.getMode().toString()
                    );
                }

                // 마스킹된 데이터 반환
                return ResponseEntity.ok(createResponse(data.getMaskedCopy(), true));

            } else {
                log.info("Customer data not found - ID: {}", customerId);
                return ResponseEntity.notFound().build();
            }

        } catch (SecurityException e) {
            // 보안 체크에 의해 접근 거부됨
            log.info("Access denied by security system - Customer: {}, Reason: {}",
                    customerId, e.getMessage());

            // 접근 실패 기록
            if (context != null && context.isSimulation()) {
                dataBreachTracker.recordAccessAttempt(
                    context.getCampaignId(),
                    context.getAttackId(),
                    actualAttackType != null ? actualAttackType : "UNKNOWN",
                    customerId,
                    false, // 실패
                    context.getMode().toString()
                );
            }

            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(createErrorResponse("Access Denied", e.getMessage()));

        } catch (Exception e) {
            log.error("Unexpected error accessing customer data", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Internal Error", "Failed to process request"));
        }
    }

    /**
     * 여러 고객 데이터 일괄 조회 (대량 유출 시나리오)
     *
     * @param customerIds 조회할 고객 ID 목록
     * @return 고객 데이터 목록 또는 접근 거부
     */
    @PostMapping("/customers/bulk")
    public ResponseEntity<?> getBulkCustomerData(@RequestBody List<String> customerIds) {

        SimulationModeHolder.SimulationContext context = SimulationModeHolder.getContext();

        log.warn("BULK customer data access attempt - Count: {}, Mode: {}",
                customerIds.size(), context != null ? context.getMode() : "NORMAL");

        if (customerIds.size() > 100) {
            log.error("SUSPICIOUS: Bulk request for {} customers", customerIds.size());
        }

        try {
            // 시뮬레이션 모드에서는 자율보안운영체제가 백그라운드에서 위협 평가를 완료할 시간 제공
            /*if (context != null && context.isSimulation()) {
                log.debug("Waiting for autonomous security system to complete threat assessment for bulk access...");
                Thread.sleep(2500); // 2.5초 대기
            }*/

            List<Map<String, Object>> results = new ArrayList<>();
            int successCount = 0;
            int failedCount = 0;

            for (String customerId : customerIds) {
                try {
                    Optional<CustomerData> dataOpt = protectableDataService.getCustomerData(customerId);
                    if (dataOpt.isPresent()) {
                        results.add(createResponse(dataOpt.get().getMaskedCopy(), true));
                        successCount++;

                        // 대량 유출 기록
                        if (context != null && context.isSimulation()) {
                            dataBreachTracker.recordDataBreach(
                                context.getCampaignId(),
                                context.getAttackId() + "-bulk",
                                "BULK_DATA_EXFILTRATION",
                                dataOpt.get(),
                                context.getMode().toString()
                            );
                        }
                    }
                } catch (Exception e) {
                    failedCount++;
                    log.debug("Failed to access customer: {}", customerId);
                }
            }

            log.warn("Bulk access completed - Success: {}, Failed: {}", successCount, failedCount);

            Map<String, Object> response = new HashMap<>();
            response.put("totalRequested", customerIds.size());
            response.put("successCount", successCount);
            response.put("failedCount", failedCount);
            response.put("data", results);
            response.put("timestamp", LocalDateTime.now());

            return ResponseEntity.ok(response);

        } catch (SecurityException e) {
            log.info("Bulk access denied by security system");
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(createErrorResponse("Bulk Access Denied", e.getMessage()));

        } catch (Exception e) {
            log.error("Error in bulk customer data access", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Bulk Processing Error", "Failed to process bulk request"));
        }
    }

    /**
     * 고객 데이터 수정 시도 (권한 상승 공격 시나리오)
     *
     * @param customerId 수정할 고객 ID
     * @param updateData 수정 데이터
     * @return 수정 결과 또는 접근 거부
     */
    @PutMapping("/customer/{customerId}")
    public ResponseEntity<?> updateCustomerData(
            @PathVariable String customerId,
            @RequestBody Map<String, Object> updateData) {

        log.error("Customer data UPDATE attempt - ID: {}", customerId);

        // 시뮬레이션 컨텍스트 확인
        SimulationModeHolder.SimulationContext context = SimulationModeHolder.getContext();

        try {
            // 시뮬레이션 모드에서는 자율보안운영체제가 백그라운드에서 위협 평가를 완료할 시간 제공
            /*if (context != null && context.isSimulation()) {
                log.debug("Waiting for autonomous security system to complete threat assessment for update operation...");
                try {
                    Thread.sleep(2500); // 2.5초 대기
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    log.warn("Thread interrupted during autonomous security system wait");
                }
            }*/

            // 실제로는 수정하지 않고 시뮬레이션만
            log.warn("UPDATE operation would modify customer: {}", customerId);

            return ResponseEntity.ok(Map.of(
                "message", "Update simulated",
                "customerId", customerId,
                "wouldUpdate", updateData.keySet()
            ));

        } catch (SecurityException e) {
            log.info("Update denied by security system - Customer: {}", customerId);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(createErrorResponse("Update Denied", e.getMessage()));
        }
    }

    /**
     * 고객 데이터 삭제 시도 (파괴적 공격 시나리오)
     *
     * @param customerId 삭제할 고객 ID
     * @return 삭제 결과 또는 접근 거부
     */
    @DeleteMapping("/customer/{customerId}")
    public ResponseEntity<?> deleteCustomerData(@PathVariable String customerId) {

        log.error("Customer data DELETE attempt - ID: {}", customerId);

        // 시뮬레이션 컨텍스트 확인
        SimulationModeHolder.SimulationContext context = SimulationModeHolder.getContext();

        try {
            // 시뮬레이션 모드에서는 자율보안운영체제가 백그라운드에서 위협 평가를 완료할 시간 제공
            /*if (context != null && context.isSimulation()) {
                log.debug("Waiting for autonomous security system to complete threat assessment for delete operation...");
                try {
                    Thread.sleep(2500); // 2.5초 대기
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    log.warn("Thread interrupted during autonomous security system wait");
                }
            }*/

            // 실제로는 삭제하지 않고 시뮬레이션만
            log.error("DELETE operation would remove customer: {}", customerId);

            return ResponseEntity.ok(Map.of(
                "message", "Delete simulated",
                "customerId", customerId,
                "wouldDelete", true
            ));

        } catch (SecurityException e) {
            log.info("Delete denied by security system - Customer: {}", customerId);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(createErrorResponse("Delete Denied", e.getMessage()));
        }
    }

    /**
     * 응답 생성 헬퍼 메서드
     */
    private Map<String, Object> createResponse(CustomerData data, boolean success) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", success);
        response.put("timestamp", LocalDateTime.now());

        if (data != null) {
            response.put("customerId", data.getCustomerId());
            response.put("name", data.getName());
            response.put("email", data.getEmail());
            response.put("sensitivityLevel", data.getSensitivityLevel());
            response.put("isVip", data.getIsVip());
        }

        return response;
    }

    /**
     * 에러 응답 생성 헬퍼 메서드
     */
    private Map<String, Object> createErrorResponse(String error, String message) {
        return Map.of(
            "error", error,
            "message", message,
            "timestamp", LocalDateTime.now()
        );
    }
}