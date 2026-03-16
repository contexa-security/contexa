package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.springbootstartercontexa.service.TestSecurityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.http.MediaType;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 보안 플로우 테스트용 REST 컨트롤러
 *
 * TestSecurityService의 @Protectable 메서드를 호출하여
 * 실제 보안 플로우를 테스트한다.
 *
 * 각 엔드포인트는 서비스 메서드를 호출하고, 결과 또는 예외를 JSON으로 반환한다.
 */
@Slf4j
@RestController
@RequestMapping("/api/security-test")
@RequiredArgsConstructor
public class TestSecurityController {

    private final TestSecurityService testSecurityService;

    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    /**
     * 공개 데이터 조회 테스트
     *
     * 서비스 메서드: TestSecurityService.getPublicData(String)
     * AnalysisRequirement: NOT_REQUIRED
     * 정책: 인증된 사용자만 (Action 무관)
     *
     * @param resourceId 리소스 식별자
     * @return 조회 결과 또는 에러 응답
     */
    @GetMapping("/public/{resourceId}")
    public ResponseEntity<Map<String, Object>> testPublicData(
            @PathVariable String resourceId) {

        long startTime = System.currentTimeMillis();
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        log.info("[보안 테스트] 공개 데이터 조회 시작 - user: {}, resourceId: {}",
            auth != null ? auth.getName() : "anonymous", resourceId);

        try {
            String result = testSecurityService.getPublicData(resourceId);
            long processingTime = System.currentTimeMillis() - startTime;

            log.info("[보안 테스트] 공개 데이터 조회 성공 - processingTime: {}ms", processingTime);

            return ResponseEntity.ok(createSuccessResponse(
                result, resourceId, "NOT_REQUIRED", processingTime, timestamp, auth));

        } catch (AccessDeniedException e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.warn("[보안 테스트] 공개 데이터 조회 차단 - reason: {}, processingTime: {}ms",
                e.getMessage(), processingTime);

            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(createErrorResponse(e, resourceId, "NOT_REQUIRED", processingTime, timestamp, auth));

        } catch (IllegalArgumentException e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.warn("[보안 테스트] 공개 데이터 조회 실패 - reason: {}", e.getMessage());

            return ResponseEntity.badRequest()
                .body(createValidationErrorResponse(e, resourceId, processingTime, timestamp));

        } catch (Exception e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.error("[보안 테스트] 공개 데이터 조회 오류", e);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(createErrorResponse(e, resourceId, "NOT_REQUIRED", processingTime, timestamp, auth));
        }
    }

    /**
     * 일반 데이터 조회 테스트
     *
     * 서비스 메서드: TestSecurityService.getNormalData(String)
     * AnalysisRequirement: PREFERRED
     * 정책: #trust.hasAction('ALLOW') and hasRole('USER')
     *
     * @param resourceId 리소스 식별자
     * @return 조회 결과 또는 에러 응답
     */
    @GetMapping("/normal/{resourceId}")
    public ResponseEntity<Map<String, Object>> testNormalData(
            @PathVariable String resourceId) {

        long startTime = System.currentTimeMillis();
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        log.info("[보안 테스트] 일반 데이터 조회 시작 - user: {}, resourceId: {}",
            auth != null ? auth.getName() : "anonymous", resourceId);

        try {
            String result = testSecurityService.getNormalData(resourceId);
            long processingTime = System.currentTimeMillis() - startTime;

            log.info("[보안 테스트] 일반 데이터 조회 성공 - processingTime: {}ms", processingTime);

            return ResponseEntity.ok(createSuccessResponse(
                result, resourceId, "PREFERRED", processingTime, timestamp, auth));

        } catch (AccessDeniedException e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.warn("[보안 테스트] 일반 데이터 조회 차단 - reason: {}, processingTime: {}ms",
                e.getMessage(), processingTime);

            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(createErrorResponse(e, resourceId, "PREFERRED", processingTime, timestamp, auth));

        } catch (IllegalArgumentException e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.warn("[보안 테스트] 일반 데이터 조회 실패 - reason: {}", e.getMessage());

            return ResponseEntity.badRequest()
                .body(createValidationErrorResponse(e, resourceId, processingTime, timestamp));

        } catch (Exception e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.error("[보안 테스트] 일반 데이터 조회 오류", e);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(createErrorResponse(e, resourceId, "PREFERRED", processingTime, timestamp, auth));
        }
    }

    /**
     * 민감 데이터 조회 테스트
     *
     * 서비스 메서드: TestSecurityService.getSensitiveData(String)
     * AnalysisRequirement: REQUIRED
     * 정책: #trust.requiresAnalysisWithAction('ALLOW') and hasRole('USER')
     *
     * @param resourceId 리소스 식별자
     * @return 조회 결과 또는 에러 응답
     */
    @GetMapping("/sensitive/{resourceId}")
    public ResponseEntity<Map<String, Object>> testSensitiveData(
            @PathVariable String resourceId) {

        long startTime = System.currentTimeMillis();
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        log.info("[보안 테스트] 민감 데이터 조회 시작 - user: {}, resourceId: {}",
            auth != null ? auth.getName() : "anonymous", resourceId);

        try {
            String result = testSecurityService.getSensitiveData(resourceId);
            long processingTime = System.currentTimeMillis() - startTime;

            log.info("[보안 테스트] 민감 데이터 조회 성공 - processingTime: {}ms", processingTime);

            return ResponseEntity.ok(createSuccessResponse(
                result, resourceId, "REQUIRED", processingTime, timestamp, auth));

        } catch (AccessDeniedException e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.warn("[보안 테스트] 민감 데이터 조회 차단 - reason: {}, processingTime: {}ms",
                e.getMessage(), processingTime);

            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(createErrorResponse(e, resourceId, "REQUIRED", processingTime, timestamp, auth));

        } catch (IllegalArgumentException e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.warn("[보안 테스트] 민감 데이터 조회 실패 - reason: {}", e.getMessage());

            return ResponseEntity.badRequest()
                .body(createValidationErrorResponse(e, resourceId, processingTime, timestamp));

        } catch (Exception e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.error("[보안 테스트] 민감 데이터 조회 오류", e);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(createErrorResponse(e, resourceId, "REQUIRED", processingTime, timestamp, auth));
        }
    }

    /**
     * 중요 데이터 조회 테스트
     *
     * 서비스 메서드: TestSecurityService.getCriticalData(String)
     * AnalysisRequirement: STRICT
     * 정책: hasRole('ADMIN') and #trust.requiresAnalysisWithAction('ALLOW')
     *
     * @param resourceId 리소스 식별자
     * @return 조회 결과 또는 에러 응답
     */
    @GetMapping("/critical/{resourceId}")
    public ResponseEntity<Map<String, Object>> testCriticalData(
            @PathVariable String resourceId) {

        long startTime = System.currentTimeMillis();
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        log.info("[보안 테스트] 중요 데이터 조회 시작 - user: {}, resourceId: {}",
            auth != null ? auth.getName() : "anonymous", resourceId);

        try {
            String result = testSecurityService.getCriticalData(resourceId);
            long processingTime = System.currentTimeMillis() - startTime;

            log.info("[보안 테스트] 중요 데이터 조회 성공 - processingTime: {}ms", processingTime);

            return ResponseEntity.ok(createSuccessResponse(
                result, resourceId, "STRICT", processingTime, timestamp, auth));

        } catch (AccessDeniedException e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.warn("[보안 테스트] 중요 데이터 조회 차단 - reason: {}, processingTime: {}ms",
                e.getMessage(), processingTime);

            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(createErrorResponse(e, resourceId, "STRICT", processingTime, timestamp, auth));

        } catch (IllegalArgumentException e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.warn("[보안 테스트] 중요 데이터 조회 실패 - reason: {}", e.getMessage());

            return ResponseEntity.badRequest()
                .body(createValidationErrorResponse(e, resourceId, processingTime, timestamp));

        } catch (Exception e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.error("[보안 테스트] 중요 데이터 조회 오류", e);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(createErrorResponse(e, resourceId, "STRICT", processingTime, timestamp, auth));
        }
    }

    /**
     * 대량 데이터 조회 테스트
     *
     * 서비스 메서드: TestSecurityService.getBulkData()
     * AnalysisRequirement: PREFERRED + enableRuntimeInterception
     * 정책: #trust.hasActionOrDefault('ALLOW', 'ALLOW')
     *
     * @return 조회 결과 또는 에러 응답
     */
    @GetMapping("/bulk")
    public ResponseEntity<Map<String, Object>> testBulkData() {

        long startTime = System.currentTimeMillis();
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        log.info("[보안 테스트] 대량 데이터 조회 시작 - user: {}",
            auth != null ? auth.getName() : "anonymous");

        try {
            String result = testSecurityService.getBulkData();
            long processingTime = System.currentTimeMillis() - startTime;

            log.info("[보안 테스트] 대량 데이터 조회 성공 - dataLength: {}, processingTime: {}ms",
                result.length(), processingTime);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("timestamp", timestamp);
            response.put("user", auth != null ? auth.getName() : "anonymous");
            response.put("analysisRequirement", "PREFERRED (Runtime Interception)");
            response.put("dataLength", result.length());
            response.put("recordCount", 10000);
            response.put("processingTime", processingTime);

            return ResponseEntity.ok(response);

        } catch (AccessDeniedException e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.warn("[보안 테스트] 대량 데이터 조회 차단 - reason: {}, processingTime: {}ms",
                e.getMessage(), processingTime);

            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(createErrorResponse(e, "bulk", "PREFERRED (Runtime Interception)", processingTime, timestamp, auth));

        } catch (Exception e) {
            long processingTime = System.currentTimeMillis() - startTime;
            log.error("[보안 테스트] 대량 데이터 조회 오류", e);

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(createErrorResponse(e, "bulk", "PREFERRED (Runtime Interception)", processingTime, timestamp, auth));
        }
    }

    /**
     * Streaming bulk data endpoint for response blocking demo
     *
     * Generates 10,000 employee records streamed over ~20 seconds.
     * Each flush triggers BlockableServletOutputStream.checkBlocked(),
     * enabling real-time response termination by AI security decisions.
     */
    @GetMapping("/bulk-stream")
    public ResponseEntity<StreamingResponseBody> testBulkStream() {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : "anonymous";

        log.info("[Security Test] Bulk stream started - user: {}", username);

        try {
            testSecurityService.validateBulkStreamAccess();
        } catch (AccessDeniedException e) {
            log.error("[Security Test] Bulk stream access denied - user: {}, reason: {}", username, e.getMessage());
            StreamingResponseBody errorBody = outputStream -> {
                String error = "{\"error\":\"ACCESS_DENIED\",\"message\":\"" + e.getMessage() + "\"}";
                outputStream.write(error.getBytes(StandardCharsets.UTF_8));
                outputStream.flush();
            };
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(errorBody);
        }

        StreamingResponseBody body = outputStream -> {
            int totalRecords = 100000;

            for (int i = 1; i <= totalRecords; i++) {
                String record = generateEmployeeRecord(i);
                outputStream.write(record.getBytes(StandardCharsets.UTF_8));

                if (i % 100 == 0) {
                    outputStream.flush();
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }

            outputStream.flush();
            log.info("[Security Test] Bulk stream completed - user: {}", username);
        };

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header("X-Total-Records", "10000")
                .header("Cache-Control", "no-cache")
                .body(body);
    }

    private static final String[] LAST_NAMES = {
        "Kim", "Lee", "Park", "Choi", "Jung", "Kang", "Cho", "Yoon", "Jang", "Lim",
        "Han", "Oh", "Seo", "Shin", "Kwon", "Hwang", "Ahn", "Song", "Yoo", "Hong"
    };

    private static final String[] FIRST_NAMES = {
        "Minjun", "Soyeon", "Jihoon", "Yuna", "Seojin", "Hajin", "Doyeon", "Hyunwoo",
        "Eunji", "Taehyun", "Jiwon", "Subin", "Yeji", "Junhyeok", "Chaeyoung", "Dongwook"
    };

    private static final String[] DEPARTMENTS = {
        "Engineering", "HR", "Finance", "Marketing", "Sales", "Operations",
        "Legal", "R&D", "Security", "Product", "Design", "QA"
    };

    private String generateEmployeeRecord(int index) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        String lastName = LAST_NAMES[rng.nextInt(LAST_NAMES.length)];
        String firstName = FIRST_NAMES[rng.nextInt(FIRST_NAMES.length)];
        String dept = DEPARTMENTS[rng.nextInt(DEPARTMENTS.length)];
        int salary = 45_000_000 + rng.nextInt(80_000_000);
        int birthYear = 70 + rng.nextInt(30);
        int gender = rng.nextInt(2) + 1;

        return String.format("EMP-%05d | %-15s | %-12s | %,11d KRW | SSN: %d***-%d****** | %s.%s@company.com\n",
                index,
                lastName + " " + firstName,
                dept,
                salary,
                birthYear,
                gender,
                firstName.toLowerCase(),
                lastName.toLowerCase());
    }

    /**
     * 성공 응답 생성
     */
    private Map<String, Object> createSuccessResponse(
            String data, String resourceId, String analysisRequirement,
            long processingTime, String timestamp, Authentication auth) {

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", true);
        response.put("timestamp", timestamp);
        response.put("user", auth != null ? auth.getName() : "anonymous");
        response.put("resourceId", resourceId);
        response.put("analysisRequirement", analysisRequirement);
        response.put("data", data);
        response.put("processingTime", processingTime);

        return response;
    }

    /**
     * 에러 응답 생성
     */
    private Map<String, Object> createErrorResponse(
            Exception e, String resourceId, String analysisRequirement,
            long processingTime, String timestamp, Authentication auth) {

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", false);
        response.put("timestamp", timestamp);
        response.put("user", auth != null ? auth.getName() : "anonymous");
        response.put("resourceId", resourceId);
        response.put("analysisRequirement", analysisRequirement);
        response.put("error", e.getClass().getSimpleName());
        response.put("message", e.getMessage());
        response.put("processingTime", processingTime);

        // AccessDeniedException인 경우 추가 정보
        if (e instanceof AccessDeniedException) {
            response.put("blocked", true);
            response.put("blockReason", extractBlockReason(e.getMessage()));
        }

        return response;
    }

    /**
     * 유효성 검사 오류 응답 생성
     */
    private Map<String, Object> createValidationErrorResponse(
            IllegalArgumentException e, String resourceId,
            long processingTime, String timestamp) {

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", false);
        response.put("timestamp", timestamp);
        response.put("resourceId", resourceId);
        response.put("error", "ValidationError");
        response.put("message", e.getMessage());
        response.put("processingTime", processingTime);

        return response;
    }

    /**
     * 차단 사유 추출
     */
    private String extractBlockReason(String message) {
        if (message == null) {
            return "Unknown";
        }
        if (message.contains(ZeroTrustAction.BLOCK.name())) {
            return "LLM Action: BLOCK";
        }
        if (message.contains(ZeroTrustAction.PENDING_ANALYSIS.name())) {
            return "Analysis not completed (timeout)";
        }
        if (message.contains("MONITOR") && message.contains("STRICT")) {
            return "STRICT mode requires ALLOW action";
        }
        if (message.contains("Access Denied") || message.contains("Access is denied")) {
            return "Policy evaluation failed";
        }
        return message;
    }
}
