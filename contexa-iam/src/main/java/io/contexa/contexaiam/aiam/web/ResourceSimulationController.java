package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.domain.entity.CustomerData;
import io.contexa.contexacore.simulation.tracker.DataBreachTracker;
import io.contexa.contexaiam.aiam.service.ProtectableDataService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 리소스 및 데이터 접근 시뮬레이션 API
 *
 * API 키 노출, 데이터 유출, 권한 상승 등의 공격을 시뮬레이션하고
 * 실시간으로 보안 이벤트를 발행합니다.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ResourceSimulationController {

    private final AttackEventHelper attackEventHelper;
    private final ProtectableDataService protectableDataService;
    private final DataBreachTracker dataBreachTracker;

    /**
     * JavaScript 파일 접근 - API 키 노출 탐지 + 고객 데이터 접근 시도
     */
    @GetMapping("/js/app.js")
    public ResponseEntity<String> getJavaScript(
            @RequestHeader(value = "X-Simulation-Mode", required = false) String simulationMode,
            @RequestHeader(value = "X-Simulation-Campaign", required = false) String campaignId,
            @RequestHeader(value = "X-Target-Customer", required = false) String targetCustomerId) {

        log.warn("클라이언트 JavaScript 파일 요청 - Mode: {}", simulationMode);

        // API 키 노출 시뮬레이션 (테스트용)
        String jsContent = """
            // App configuration
            const config = {
                apiEndpoint: 'https://api.example.com',
                apiKey: 'YOUR_API_KEY_HERE',  // 환경 변수에서 로드 필요
                analyticsKey: 'YOUR_ANALYTICS_KEY'
            };

            function initApp() {
                console.log('App initialized');
            }
            """;

        // 시뮬레이션 모드일 때 고객 데이터 접근 시도
        if (simulationMode != null && targetCustomerId != null) {
            try {
                // 시뮬레이션 컨텍스트가 이미 인터셉터에서 설정되어 있음
                io.contexa.contexacore.simulation.context.SimulationModeHolder.SimulationContext context =
                    io.contexa.contexacore.simulation.context.SimulationModeHolder.getContext();

                if (context != null && context.shouldBypassSecurity()) {
                    // 무방비 모드 - 직접 접근
                    Optional<CustomerData> data =
                        protectableDataService.getCustomerDataDirect(targetCustomerId);

                    if (data.isPresent()) {
                        log.error("UNPROTECTED: Customer data exposed via API key vulnerability - ID: {}",
                                targetCustomerId);
                        dataBreachTracker.recordDataBreach(
                            campaignId != null ? campaignId : "unknown",
                            UUID.randomUUID().toString(),
                            "API_KEY_EXPOSURE",
                            data.get(),
                            "UNPROTECTED"
                        );
                    }
                } else if (context != null) {
                    // 방어 모드 - 보안 체크 수행
                    try {
                        Optional<CustomerData> data =
                            protectableDataService.getCustomerData(targetCustomerId);

                        if (data.isPresent()) {
                            log.warn("PROTECTED: Unexpected data access despite security - ID: {}",
                                    targetCustomerId);
                        }
                    } catch (Exception e) {
                        log.info("PROTECTED: Access blocked - {}", e.getMessage());
                        dataBreachTracker.recordAccessAttempt(
                            campaignId != null ? campaignId : "unknown",
                            UUID.randomUUID().toString(),
                            "API_KEY_EXPOSURE",
                            targetCustomerId,
                            false,
                            "PROTECTED"
                        );
                    }
                }
            } catch (Exception e) {
                log.error("Error in customer data access attempt", e);
            }
        }

        // API 키 노출 이벤트 발행 (방어 모드에서만)
        if (!"UNPROTECTED".equals(simulationMode)) {
            AttackResult event = AttackResult.builder()
                .attackId(UUID.randomUUID().toString())
                .attackType(AttackResult.AttackType.API_KEY_EXPOSURE)
                .username("anonymous")
                .targetResource("/js/app.js")
                .timestamp(LocalDateTime.now())
                .riskScore(0.9)
                .details(Map.of(
                    "exposedKeys", List.of("sk_live_4242424242424242"),
                    "fileType", "javascript"
                ))
                .build();

            attackEventHelper.publishAttackEvent(
                event,
                "API_KEY_IN_JAVASCRIPT",
                "API key exposed in client-side JavaScript"
            );
        }

        return ResponseEntity.ok(jsContent);
    }

    /**
     * 에러 페이지 API - 스택 트레이스 노출
     */
    @GetMapping("/api/error")
    @PostMapping("/api/error")
    public ResponseEntity<?> errorPage(@RequestParam Map<String, String> params) {
        String errorCode = params.get("code");
        boolean debug = "true".equals(params.get("debug"));

        log.error("에러 페이지 접근: code={}, debug={}", errorCode, debug);

        Map<String, Object> response = new HashMap<>();
        response.put("error", errorCode != null ? errorCode : "INTERNAL_ERROR");
        response.put("timestamp", LocalDateTime.now());

        // 디버그 모드에서 민감한 정보 노출
        if (debug) {
            response.put("stackTrace", generateStackTrace());
            response.put("environment", Map.of(
                "database", "postgresql://db.internal:5432/production",
                "redis", "redis://cache.internal:6379",
                "apiKey", "sk_test_" + UUID.randomUUID().toString().substring(0, 8)
            ));

            // 스택 트레이스 노출 이벤트
            AttackResult event = AttackResult.builder()
                .attackId(UUID.randomUUID().toString())
                .attackType(AttackResult.AttackType.API_KEY_EXPOSURE)
                .username("error-viewer")
                .targetResource("/api/error")
                .timestamp(LocalDateTime.now())
                .riskScore(0.8)
                .details(Map.of(
                    "debugMode", true,
                    "exposedInfo", "stack_trace_and_config"
                ))
                .build();

            attackEventHelper.publishAttackEvent(
                event,
                "DEBUG_INFO_EXPOSURE",
                "Sensitive debug information exposed"
            );
        }

        return ResponseEntity.status(500).body(response);
    }

    /**
     * 모바일 앱 분석 API - API 키 추출 시뮬레이션
     */
    @PostMapping("/api/mobile/analyze")
    public ResponseEntity<?> analyzeMobileApp(@RequestBody Map<String, Object> request) {
        String appPackage = (String) request.get("package");
        String version = (String) request.get("version");

        log.warn("모바일 앱 분석 요청: package={}, version={}", appPackage, version);

        // 모바일 앱에서 API 키 추출 시뮬레이션
        Map<String, Object> analysis = new HashMap<>();
        analysis.put("package", appPackage);
        analysis.put("version", version);

        // 하드코딩된 API 키 발견 시뮬레이션
        if (ThreadLocalRandom.current().nextBoolean()) {
            List<String> foundKeys = List.of(
                "AIzaSyD" + UUID.randomUUID().toString().substring(0, 8),
                "pk_live_" + UUID.randomUUID().toString().substring(0, 16)
            );
            analysis.put("hardcodedKeys", foundKeys);

            AttackResult event = AttackResult.builder()
                .attackId(UUID.randomUUID().toString())
                .attackType(AttackResult.AttackType.API_KEY_EXPOSURE)
                .username("mobile-analyzer")
                .targetResource("/api/mobile/analyze")
                .timestamp(LocalDateTime.now())
                .riskScore(0.85)
                .details(Map.of(
                    "package", appPackage,
                    "keysFound", foundKeys.size()
                ))
                .build();

            attackEventHelper.publishAttackEvent(
                event,
                "MOBILE_KEY_EXTRACTION",
                "API keys found in mobile app: " + appPackage
            );
        }

        return ResponseEntity.ok(analysis);
    }

    /**
     * 브라우저 스토리지 API - 로컬 스토리지 데이터 노출
     */
    @GetMapping("/api/browser/storage")
    @PostMapping("/api/browser/storage")
    public ResponseEntity<?> browserStorage(@RequestBody(required = false) Map<String, Object> request) {
        String storageType = request != null ? (String) request.get("type") : "localStorage";

        log.info("브라우저 스토리지 접근: type={}", storageType);

        Map<String, Object> storageData = new HashMap<>();

        // 로컬 스토리지에 저장된 민감한 데이터 시뮬레이션
        if ("localStorage".equals(storageType)) {
            storageData.put("authToken", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");
            storageData.put("apiKey", "pk_test_" + UUID.randomUUID().toString().substring(0, 16));
            storageData.put("userId", UUID.randomUUID().toString());

            AttackResult event = AttackResult.builder()
                .attackId(UUID.randomUUID().toString())
                .attackType(AttackResult.AttackType.API_KEY_EXPOSURE)
                .username("browser-user")
                .targetResource("/api/browser/storage")
                .timestamp(LocalDateTime.now())
                .riskScore(0.75)
                .details(Map.of(
                    "storageType", storageType,
                    "sensitiveData", true
                ))
                .build();

            attackEventHelper.publishAttackEvent(
                event,
                "BROWSER_STORAGE_EXPOSURE",
                "Sensitive data exposed in browser storage"
            );
        }

        return ResponseEntity.ok(storageData);
    }

    /**
     * 관리자 데이터 내보내기 API - 대량 데이터 유출
     */
    @GetMapping("/api/admin/export")
    @PostMapping("/api/admin/export")
    public ResponseEntity<?> adminExport(@RequestHeader Map<String, String> headers) {
        String apiKey = headers.get("x-api-key");
        String exportType = headers.get("x-export-type");

        log.error("관리자 데이터 내보내기 시도: type={}", exportType);

        // 권한 상승 시도 탐지
        if (apiKey != null && apiKey.startsWith("sk_live_")) {
            AttackResult event = AttackResult.builder()
                .attackId(UUID.randomUUID().toString())
                .attackType(AttackResult.AttackType.PRIVILEGE_ESCALATION)
                .username("admin-exporter")
                .targetResource("/api/admin/export")
                .timestamp(LocalDateTime.now())
                .successful(false)
                .detected(true)
                .blocked(true)
                .riskScore(0.95)
                .details(Map.of(
                    "exportType", exportType != null ? exportType : "all",
                    "privilegeLevel", "admin"
                ))
                .build();

            attackEventHelper.publishAttackEvent(
                event,
                "PRIVILEGE_ESCALATION_ATTEMPT",
                "Unauthorized admin export attempt blocked"
            );

            return ResponseEntity.status(403).body(Map.of(
                "error", "FORBIDDEN",
                "message", "Insufficient privileges for admin export"
            ));
        }

        return ResponseEntity.ok(Map.of(
            "exported", 0,
            "message", "Export requires admin authentication"
        ));
    }

    /**
     * 데이터 수집 API - 파이프라인 독성 데이터 주입
     */
    @PostMapping("/api/data/ingest")
    public ResponseEntity<?> dataIngest(@RequestBody Map<String, Object> request) {
        String source = (String) request.get("source");
        List<?> data = (List<?>) request.get("data");
        String pipeline = (String) request.get("pipeline");

        log.warn("데이터 수집: source={}, pipeline={}, size={}",
            source, pipeline, data != null ? data.size() : 0);

        // 대량 독성 데이터 주입 탐지
        if (data != null && data.size() > 50) {
            boolean containsPoisonedData = false;

            // 데이터에서 독성 패턴 검사
            for (Object item : data) {
                if (item instanceof Map) {
                    Map<?, ?> dataItem = (Map<?, ?>) item;
                    if (dataItem.containsKey("poison") || dataItem.containsKey("backdoor")) {
                        containsPoisonedData = true;
                        break;
                    }
                }
            }

            if (containsPoisonedData) {
                AttackResult event = AttackResult.builder()
                    .attackId(UUID.randomUUID().toString())
                    .attackType(AttackResult.AttackType.MODEL_POISONING)
                    .username("data-injector")
                    .targetResource("/api/data/ingest")
                    .timestamp(LocalDateTime.now())
                    .riskScore(0.9)
                    .details(Map.of(
                        "source", source != null ? source : "unknown",
                        "pipeline", pipeline != null ? pipeline : "default",
                        "dataSize", data.size(),
                        "poisoned", true
                    ))
                    .build();

                attackEventHelper.publishAttackEvent(
                    event,
                    "POISONED_DATA_INJECTION",
                    "Poisoned data injection detected in pipeline: " + pipeline
                );
            }
        }

        return ResponseEntity.ok(Map.of(
            "status", "INGESTED",
            "records", data != null ? data.size() : 0,
            "pipeline", pipeline != null ? pipeline : "default"
        ));
    }

    /**
     * 일반 API 엔드포인트 - Rate Limit 및 Velocity 공격 탐지
     */
    @GetMapping("/api/{service}")
    @PostMapping("/api/{service}")
    public ResponseEntity<?> genericApiEndpoint(
            @PathVariable String service,
            @RequestHeader Map<String, String> headers,
            @RequestBody(required = false) Map<String, Object> body) {

        String clientIp = headers.get("x-forwarded-for");
        if (clientIp == null) {
            clientIp = headers.get("x-real-ip");
        }

        log.info("API 요청: service={}, ip={}", service, clientIp);

        // Rate limit bypass 시도 탐지
        if (headers.containsKey("x-originating-ip") ||
            headers.containsKey("x-remote-addr") ||
            headers.containsKey("x-client-ip")) {

            AttackResult event = AttackResult.builder()
                .attackId(UUID.randomUUID().toString())
                .attackType(AttackResult.AttackType.RATE_LIMIT_BYPASS)
                .username(clientIp != null ? clientIp : "unknown")
                .targetResource("/api/" + service)
                .timestamp(LocalDateTime.now())
                .riskScore(0.7)
                .details(Map.of(
                    "service", service,
                    "bypassHeaders", true
                ))
                .build();

            attackEventHelper.publishAttackEvent(
                event,
                "RATE_LIMIT_BYPASS_ATTEMPT",
                "Rate limit bypass attempt using header manipulation"
            );
        }

        // Velocity attack 탐지 (빠른 연속 요청)
        if (isVelocityAttack(clientIp, service)) {
            AttackResult event = AttackResult.builder()
                .attackId(UUID.randomUUID().toString())
                .attackType(AttackResult.AttackType.VELOCITY_ATTACK)
                .username(clientIp != null ? clientIp : "unknown")
                .targetResource("/api/" + service)
                .timestamp(LocalDateTime.now())
                .riskScore(0.8)
                .details(Map.of(
                    "service", service,
                    "requestRate", "high"
                ))
                .build();

            attackEventHelper.publishAttackEvent(
                event,
                "VELOCITY_ATTACK",
                "High velocity attack detected on service: " + service
            );

            return ResponseEntity.status(429).body(Map.of(
                "error", "RATE_LIMIT_EXCEEDED",
                "message", "Too many requests"
            ));
        }

        // 일반 응답
        return ResponseEntity.ok(Map.of(
            "service", service,
            "status", "OK",
            "timestamp", LocalDateTime.now()
        ));
    }

    // Helper methods

    private String generateStackTrace() {
        return """
            java.lang.NullPointerException: Cannot invoke "String.length()" because "str" is null
                at io.contexa.contexaiam..service.UserService.validateUser(UserService.java:145)
                at io.contexa.contexaiam..controller.AuthController.login(AuthController.java:67)
                at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
                at org.springframework.web.servlet.mvc.method.annotation.ServletInvocableHandlerMethod.invokeAndHandle
                at org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1067)
            Database URL: postgresql://db.internal:5432/production
            Redis Cache: redis://cache.internal:6379
            API Endpoint: https://internal-api.example.com
            """;
    }

    private boolean isVelocityAttack(String clientIp, String service) {
        // 실제로는 Redis에서 요청 빈도를 추적
        // 시뮬레이션: 15% 확률로 velocity attack으로 판단
        return ThreadLocalRandom.current().nextInt(100) < 15;
    }
}