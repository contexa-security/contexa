package io.contexa.springbootstartercontexa.web;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.springbootstartercontexa.service.SecurityTestEvidenceService;
import io.contexa.springbootstartercontexa.service.SecurityTestEvidenceService.RequestRegistration;
import io.contexa.springbootstartercontexa.service.TestSecurityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

@Slf4j
@RestController
@RequestMapping({"/api/security-test", "/admin/api/security-test"})
@RequiredArgsConstructor
public class TestSecurityController {

    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    private final TestSecurityService testSecurityService;
    private final SecurityTestEvidenceService securityTestEvidenceService;

    @GetMapping("/public/{resourceId}")
    public ResponseEntity<Map<String, Object>> testPublicData(
            @PathVariable String resourceId,
            HttpServletRequest request) {
        return executeProtectedRequest(request, resourceId, "public",
                () -> testSecurityService.getPublicData(resourceId));
    }

    @GetMapping("/normal/{resourceId}")
    public ResponseEntity<Map<String, Object>> testNormalData(
            @PathVariable String resourceId,
            HttpServletRequest request) {
        return executeProtectedRequest(request, resourceId, "normal",
                () -> testSecurityService.getNormalData(resourceId));
    }

    @GetMapping("/sensitive/{resourceId}")
    public ResponseEntity<Map<String, Object>> testSensitiveData(
            @PathVariable String resourceId,
            HttpServletRequest request) {
        return executeProtectedRequest(request, resourceId, "sensitive",
                () -> testSecurityService.getSensitiveData(resourceId));
    }

    @GetMapping("/critical/{resourceId}")
    public ResponseEntity<Map<String, Object>> testCriticalData(
            @PathVariable String resourceId,
            HttpServletRequest request) {
        return executeProtectedRequest(request, resourceId, "critical",
                () -> testSecurityService.getCriticalData(resourceId));
    }

    @GetMapping("/bulk")
    public ResponseEntity<Map<String, Object>> testBulkData(HttpServletRequest request) {
        return executeProtectedRequest(request, "bulk", "bulk",
                testSecurityService::getBulkData);
    }

    @GetMapping(value = "/bulk-stream", produces = MediaType.APPLICATION_NDJSON_VALUE)
    public StreamingResponseBody streamCurrentEvidence(
            @RequestParam(required = false) String requestId,
            HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userId = authentication != null ? authentication.getName() : "anonymous";
        String effectiveRequestId = requestId;
        if (effectiveRequestId == null || effectiveRequestId.isBlank()) {
            effectiveRequestId = request.getHeader("X-Request-ID");
        }
        return securityTestEvidenceService.streamEvidence(userId, effectiveRequestId);
    }

    @GetMapping("/demo-bulk-stream")
    public void demoBulkStream(HttpServletResponse response) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null ? auth.getName() : "anonymous";

        try {
            testSecurityService.validateBulkStreamAccess();
        } catch (AccessDeniedException exception) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\":\"ACCESS_DENIED\",\"message\":\"" + exception.getMessage() + "\"}");
            response.getWriter().flush();
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("X-Total-Records", "1000000");
        response.setHeader("Cache-Control", "no-cache");

        int totalRecords = 1000000;
        OutputStream outputStream = response.getOutputStream();
        for (int index = 1; index <= totalRecords; index++) {
            outputStream.write(generateEmployeeRecord(index).getBytes(StandardCharsets.UTF_8));
            if (index % 100 == 0) {
                outputStream.flush();
                try {
                    Thread.sleep(200L);
                } catch (InterruptedException interruptedException) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        outputStream.flush();
        log.info("[Security Test] Demo bulk stream completed - user: {}", username);
    }

    private ResponseEntity<Map<String, Object>> executeProtectedRequest(
            HttpServletRequest request,
            String resourceId,
            String endpointKey,
            ProtectedCall protectedCall) {

        long startTime = System.currentTimeMillis();
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userId = authentication != null ? authentication.getName() : "anonymous";
        RequestRegistration registration = securityTestEvidenceService.registerRequest(
                request,
                userId,
                endpointKey,
                resourceId);

        try {
            String data = protectedCall.execute();
            long processingTime = System.currentTimeMillis() - startTime;
            Map<String, Object> response = createBaseResponse(registration, resourceId, endpointKey, timestamp, authentication);
            response.put("success", true);
            response.put("httpStatus", HttpStatus.OK.value());
            response.put("resultType", "SUCCESS");
            response.put("data", data);
            response.put("processingTime", processingTime);
            securityTestEvidenceService.recordResponse(registration.getRequestId(), HttpStatus.OK.value(), true, response, processingTime);
            return ResponseEntity.ok(response);
        } catch (AccessDeniedException exception) {
            long processingTime = System.currentTimeMillis() - startTime;
            Map<String, Object> response = createBaseResponse(registration, resourceId, endpointKey, timestamp, authentication);
            response.put("success", false);
            response.put("httpStatus", HttpStatus.FORBIDDEN.value());
            response.put("resultType", "ACCESS_DENIED");
            response.put("error", exception.getClass().getSimpleName());
            response.put("message", exception.getMessage());
            response.put("processingTime", processingTime);
            response.put("blocked", true);
            response.put("blockReason", extractBlockReason(exception.getMessage()));
            response.put("resolvedActionHint", extractActionHint(exception.getMessage()));
            securityTestEvidenceService.recordResponse(registration.getRequestId(), HttpStatus.FORBIDDEN.value(), false, response, processingTime);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        } catch (IllegalArgumentException exception) {
            long processingTime = System.currentTimeMillis() - startTime;
            Map<String, Object> response = createBaseResponse(registration, resourceId, endpointKey, timestamp, authentication);
            response.put("success", false);
            response.put("httpStatus", HttpStatus.BAD_REQUEST.value());
            response.put("resultType", "VALIDATION_ERROR");
            response.put("error", "ValidationError");
            response.put("message", exception.getMessage());
            response.put("processingTime", processingTime);
            securityTestEvidenceService.recordResponse(registration.getRequestId(), HttpStatus.BAD_REQUEST.value(), false, response, processingTime);
            return ResponseEntity.badRequest().body(response);
        } catch (Exception exception) {
            long processingTime = System.currentTimeMillis() - startTime;
            Map<String, Object> response = createBaseResponse(registration, resourceId, endpointKey, timestamp, authentication);
            response.put("success", false);
            response.put("httpStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
            response.put("resultType", "ERROR");
            response.put("error", exception.getClass().getSimpleName());
            response.put("message", exception.getMessage());
            response.put("processingTime", processingTime);
            securityTestEvidenceService.recordResponse(registration.getRequestId(), HttpStatus.INTERNAL_SERVER_ERROR.value(), false, response, processingTime);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    private Map<String, Object> createBaseResponse(
            RequestRegistration registration,
            String resourceId,
            String endpointKey,
            String timestamp,
            Authentication authentication) {

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("timestamp", timestamp);
        response.put("user", authentication != null ? authentication.getName() : "anonymous");
        response.put("resourceId", resourceId);
        response.put("endpointKey", endpointKey);
        response.put("requestId", registration.getRequestId());
        response.put("correlationId", registration.getCorrelationId());
        response.put("scenario", registration.getScenario());
        response.put("expectedAction", registration.getExpectedAction());
        response.put("demoRunId", registration.getDemoRunId());
        response.put("demoPhase", registration.getDemoPhase());
        response.put("clientIp", registration.getClientIp());
        response.put("userAgent", registration.getUserAgent());
        response.put("sessionId", registration.getSessionId());
        response.put("authMode", registration.getAuthMode());
        response.put("tokenSource", registration.getTokenSource());
        response.put("authCarrier", registration.getAuthCarrier());
        response.put("authSubjectHint", registration.getAuthSubjectHint());
        response.put("authorizationHeaderPresent", registration.isAuthorizationHeaderPresent());
        response.put("requestPath", registration.getRequestPath());
        response.put("servletPath", registration.getServletPath());
        response.put("evidenceUrl", "/admin/api/security-test/evidence/" + registration.getRequestId());
        response.put("evidenceExportUrl", "/admin/api/security-test/evidence/" + registration.getRequestId() + "/export");
        response.put("evidenceStreamUrl", "/admin/api/security-test/evidence/" + registration.getRequestId() + "/stream");
        response.put("actionStatusUrl", "/admin/api/test-action/status");
        return response;
    }

    private String extractBlockReason(String message) {
        if (message == null) {
            return "Unknown";
        }
        if (message.contains(ZeroTrustAction.BLOCK.name())) {
            return "LLM Action: BLOCK";
        }
        if (message.contains(ZeroTrustAction.CHALLENGE.name())) {
            return "LLM Action: CHALLENGE";
        }
        if (message.contains(ZeroTrustAction.ESCALATE.name())) {
            return "LLM Action: ESCALATE";
        }
        if (message.contains(ZeroTrustAction.PENDING_ANALYSIS.name())) {
            return "Analysis still pending";
        }
        if (message.contains("Access Denied") || message.contains("Access is denied")) {
            return "Policy evaluation failed";
        }
        return message;
    }

    private String extractActionHint(String message) {
        if (message == null) {
            return null;
        }
        for (ZeroTrustAction action : ZeroTrustAction.values()) {
            if (message.contains(action.name())) {
                return action.name();
            }
        }
        return null;
    }

    private String generateEmployeeRecord(int index) {
        String[] lastNames = {
                "Kim", "Lee", "Park", "Choi", "Jung", "Kang", "Cho", "Yoon", "Jang", "Lim",
                "Han", "Oh", "Seo", "Shin", "Kwon", "Hwang", "Ahn", "Song", "Yoo", "Hong"
        };
        String[] firstNames = {
                "Minjun", "Soyeon", "Jihoon", "Yuna", "Seojin", "Hajin", "Doyeon", "Hyunwoo",
                "Eunji", "Taehyun", "Jiwon", "Subin", "Yeji", "Junhyeok", "Chaeyoung", "Dongwook"
        };
        String[] departments = {
                "Engineering", "HR", "Finance", "Marketing", "Sales", "Operations",
                "Legal", "R&D", "Security", "Product", "Design", "QA"
        };

        ThreadLocalRandom random = ThreadLocalRandom.current();
        String lastName = lastNames[random.nextInt(lastNames.length)];
        String firstName = firstNames[random.nextInt(firstNames.length)];
        String department = departments[random.nextInt(departments.length)];
        int salary = 45_000_000 + random.nextInt(80_000_000);
        int birthYear = 70 + random.nextInt(30);
        int gender = random.nextInt(2) + 1;

        return String.format("EMP-%05d | %-15s | %-12s | %,11d KRW | SSN: %d***-%d****** | %s.%s@company.com%n",
                index,
                lastName + " " + firstName,
                department,
                salary,
                birthYear,
                gender,
                firstName.toLowerCase(),
                lastName.toLowerCase());
    }

    @FunctionalInterface
    private interface ProtectedCall {
        String execute();
    }
}
