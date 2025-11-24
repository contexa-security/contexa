package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationFailureEvent;
import io.contexa.contexacore.domain.entity.CustomerData;
import io.contexa.contexacore.simulation.client.LoginAttackClient;
import io.contexa.contexacore.simulation.config.SimulationConfig;
import io.contexa.contexacore.simulation.factory.AttackStrategyFactory;
import io.contexa.contexaiam.aiam.service.ProtectableDataService;
import io.contexa.contexaiam.aiam.service.RealTimeBehaviorMonitor;
import io.contexa.contexaiam.security.core.CustomAuthenticationProvider;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.net.URI;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 컨텍스트 조작 컨트롤러
 *
 * HTTP 헤더를 조작하여 다양한 컨텍스트로 요청을 프록시합니다.
 * 이를 통해 Zero Trust 시스템이 순수하게 컨텍스트만으로 위협을 탐지하는지 검증합니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@RequestMapping("/context-proxy")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class ContextManipulationController {

    private final ApplicationEventPublisher eventPublisher;
    private final CustomAuthenticationProvider customAuthenticationProvider;
    private final ProtectableDataService protectableDataService;
    private final RealTimeBehaviorMonitor behaviorMonitor;
    private final RestTemplate restTemplate = new RestTemplate();

    @Autowired
    private SimulationConfig simulationConfig;

    // 실제 공격 클라이언트 통합 (선택적)
    @Autowired(required = false)
    private LoginAttackClient loginAttackClient;

    @Autowired(required = false)
    private AttackStrategyFactory attackStrategyFactory;

    @Value("${server.port:8080}")
    private int serverPort;

    // 세션별 컨텍스트 저장
    private final Map<String, ContextState> contextStates = new ConcurrentHashMap<>();

    /**
     * 컨텍스트 설정 API
     */
    @PostMapping("/configure")
    public ResponseEntity<?> configureContext(
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) String userAgent,
            @RequestParam(required = false) String language,
            @RequestParam(required = false) String time,
            HttpSession session) {

        String sessionId = session.getId();
        ContextState state = contextStates.computeIfAbsent(sessionId, k -> new ContextState());

        if (ip != null) state.setCurrentIp(ip);
        if (userAgent != null) state.setCurrentUserAgent(userAgent);
        if (language != null) state.setCurrentLanguage(language);
        if (time != null) state.setSimulatedTime(LocalTime.parse(time));

        state.setSessionId(sessionId);

        log.info("Context configured for session {}: IP={}, UA={}, Lang={}, Time={}",
                sessionId, state.getCurrentIp(), state.getCurrentUserAgent(),
                state.getCurrentLanguage(), state.getSimulatedTime());

        return ResponseEntity.ok(Map.of(
            "status", "configured",
            "context", state,
            "sessionId", sessionId
        ));
    }

    /**
     * 프록시 로그인 - 조작된 컨텍스트로 인증 시도
     */
    @PostMapping("/login")
    public ResponseEntity<?> proxyLogin(
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) String userAgent,
            @RequestParam(required = false) String language,
            @RequestParam(required = false) String time,
            @RequestParam(required = false) String contextType,
            HttpServletRequest request,
            HttpServletResponse response,
            HttpSession session) {

        String sessionId = session.getId();
        ContextState state = contextStates.computeIfAbsent(sessionId, k -> new ContextState());

        // UI에서 전달된 컨텍스트 설정 적용 (프리셋보다 우선)
        if (ip != null) state.setCurrentIp(ip);
        if (userAgent != null) state.setCurrentUserAgent(userAgent);
        if (language != null) state.setCurrentLanguage(language);
        if (time != null) state.setSimulatedTime(LocalTime.parse(time));

        // 컨텍스트 타입이 프리셋인 경우에만 자동 설정 (custom이 아닌 경우)
        if ("attacker".equals(contextType)) {
            // 공격자 프리셋이 선택된 경우에만 덮어쓰기
            if (simulationConfig.getAttackIps().getSuspicious() != null && simulationConfig.getAttackIps().getSuspicious().size() > 2) {
                state.setCurrentIp(simulationConfig.getAttackIps().getSuspicious().get(2));
            } else {
                state.setCurrentIp("185.220.101.45"); // 기본 Tor IP
            }

            if (simulationConfig.getUserAgents().getSuspicious() != null && simulationConfig.getUserAgents().getSuspicious().size() > 6) {
                state.setCurrentUserAgent(simulationConfig.getUserAgents().getSuspicious().get(6));
            } else {
                state.setCurrentUserAgent("python-requests/2.31.0");
            }

            state.setCurrentLanguage("ru-RU");
            state.setSimulatedTime(LocalTime.of(3, 0)); // 새벽 3시

        } else if ("insider".equals(contextType)) {
            // 내부자 프리셋
            if (simulationConfig.getAttackIps().getNormal() != null &&
                simulationConfig.getAttackIps().getNormal().getTrusted() != null &&
                !simulationConfig.getAttackIps().getNormal().getTrusted().isEmpty()) {
                state.setCurrentIp(simulationConfig.getAttackIps().getNormal().getTrusted().get(0));
            } else {
                state.setCurrentIp("192.168.1.100");
            }

            if (simulationConfig.getUserAgents().getNormal() != null && !simulationConfig.getUserAgents().getNormal().isEmpty()) {
                state.setCurrentUserAgent(simulationConfig.getUserAgents().getNormal().get(0));
            } else {
                state.setCurrentUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0");
            }

            state.setCurrentLanguage("ko-KR");
            state.setSimulatedTime(LocalTime.of(22, 30)); // 늦은 밤 10시 30분

        } else if ("normal".equals(contextType)) {
            // 정상 프리셋
            if (simulationConfig.getAttackIps().getNormal() != null &&
                simulationConfig.getAttackIps().getNormal().getTrusted() != null &&
                !simulationConfig.getAttackIps().getNormal().getTrusted().isEmpty()) {
                state.setCurrentIp(simulationConfig.getAttackIps().getNormal().getTrusted().get(0));
            } else {
                state.setCurrentIp("192.168.1.100");
            }

            if (simulationConfig.getUserAgents().getNormal() != null && !simulationConfig.getUserAgents().getNormal().isEmpty()) {
                state.setCurrentUserAgent(simulationConfig.getUserAgents().getNormal().get(0));
            } else {
                state.setCurrentUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0");
            }

            state.setCurrentLanguage("ko-KR");
            state.setSimulatedTime(LocalTime.of(14, 0)); // 오후 2시
        }
        // contextType이 'custom'이면 UI에서 전달된 값을 그대로 사용

        try {
            // 인증 시도
            ProviderManager providerManager = new ProviderManager(List.of(customAuthenticationProvider));
            Authentication authRequest = new UsernamePasswordAuthenticationToken(username, password);
            Authentication authResult = providerManager.authenticate(authRequest);
            HttpSessionSecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();
            SecurityContextHolder.getContext().setAuthentication(authResult);
            contextRepository.saveContext(SecurityContextHolder.getContext(),request,response);
            state.setUserId(username);

            // 인증 성공 이벤트 발행 (조작된 컨텍스트 포함)
            AuthenticationSuccessEvent successEvent = AuthenticationSuccessEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .userId(username)
                    .username(username)
                    .sessionId(sessionId)
                    .eventTimestamp(LocalDateTime.now())
                    .sourceIp(state.getCurrentIp())
                    .userAgent(state.getCurrentUserAgent())
                    .build();

            eventPublisher.publishEvent(successEvent);

      /*      // 실시간 행동 모니터링 발행
            behaviorMonitor.publishBehaviorEvent(
                username,
                "LOGIN_SUCCESS",
                state.getCurrentIp(),
                calculateRiskScore(state)
            );*/

            log.info("Proxy login successful: user={}, context={}", username, contextType);

            return ResponseEntity.ok(Map.of(
                "status", "success",
                "username", username,
                "context", state,
                "sessionId", sessionId,
                "contextType", contextType != null ? contextType : "custom",
                "message", "Authentication successful with context: " + contextType
            ));

        } catch (AuthenticationException e) {
            // 인증 실패 이벤트
            AuthenticationFailureEvent failureEvent = AuthenticationFailureEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .userId(username)
                    .username(username)
                    .sessionId(sessionId)
                    .eventTimestamp(LocalDateTime.now())
                    .sourceIp(state.getCurrentIp())
                    .userAgent(state.getCurrentUserAgent())
                    .failureReason(e.getMessage())
                    .exceptionClass(e.getClass().getName())
                    .exceptionMessage(e.getMessage())
                    .build();

            eventPublisher.publishEvent(failureEvent);

            log.warn("Proxy login failed: user={}, reason={}", username, e.getMessage());

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "status", "failed",
                "reason", e.getMessage(),
                "context", state
            ));
        }
    }

    /**
     * 프록시 데이터 접근 - @Protectable 리소스 접근
     */
    @GetMapping("/protected/customer/{customerId}")
    public ResponseEntity<?> proxyProtectedAccess(
            @PathVariable String customerId,
            @RequestParam(required = false) String accessPattern,
            HttpSession session) {

        String sessionId = session.getId();
        ContextState state = contextStates.getOrDefault(sessionId, new ContextState());

        if (state.getUserId() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "error", "Not authenticated",
                        "message", "로그인이 필요합니다. 계정 탈취 공격을 시뮬레이션하려면 먼저 로그인하세요."
                    ));
        }

        // 현재 컨텍스트 정보 로그
        log.info("Protected access attempt - User: {}, IP: {}, UA: {}, Lang: {}, Time: {}, RequestCount: {}",
                state.getUserId(), state.getCurrentIp(), state.getCurrentUserAgent(),
                state.getCurrentLanguage(), state.getSimulatedTime(), state.getRequestCount());

        state.incrementRequestCount();
        state.setLastRequestTime(LocalDateTime.now());
        state.addToHistory("ACCESS_CUSTOMER_" + customerId);

        // 접근 패턴에 따른 행동 시뮬레이션
        if ("rapid".equals(accessPattern)) {
            // 빠른 연속 접근 (공격자 패턴)
            simulateRapidAccess(state, customerId);
        } else if ("gradual".equals(accessPattern)) {
            // 점진적 증가 (내부자 위협 패턴)
            simulateGradualEscalation(state, customerId);
        }

        try {
            // @Protectable 메서드 호출 (컨텍스트가 Zero Trust에 의해 평가됨)
            Optional<CustomerData> customerData = protectableDataService.getCustomerData(customerId);

            if (customerData.isPresent()) {
                // 접근 성공 - Zero Trust가 허용함
                behaviorMonitor.publishBehaviorEvent(
                    state.getUserId(),
                    "CUSTOMER_ACCESS_SUCCESS",
                    state.getCurrentIp(),
                    calculateRiskScore(state)
                );

                log.info("Protected resource accessed: user={}, customer={}, requestCount={}",
                        state.getUserId(), customerId, state.getRequestCount());

                // 컨텍스트 기반 위험도 계산
                double contextRisk = calculateRiskScore(state);

                return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "data", customerData.get().getMaskedCopy(),
                    "context", state,
                    "accessCount", state.getRequestCount(),
                    "contextRisk", contextRisk,
                    "authContext", determineAuthContext(state),
                    "message", String.format("%s 컨텍스트로 접근 성공 (위험도: %.1f)",
                        determineAuthContext(state), contextRisk)
                ));
            } else {
                return ResponseEntity.notFound().build();
            }

        } catch (SecurityException e) {
            // Zero Trust가 접근을 차단함
            behaviorMonitor.publishBehaviorEvent(
                state.getUserId(),
                "CUSTOMER_ACCESS_BLOCKED",
                state.getCurrentIp(),
                90.0 // 높은 위험 점수
            );

            log.warn("Protected resource blocked: user={}, reason={}",
                    state.getUserId(), e.getMessage());

            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "status", "blocked",
                "reason", e.getMessage(),
                "context", state,
                "decision", "Zero Trust denied access based on context"
            ));
        }
    }

    /**
     * 대량 데이터 접근 시뮬레이션
     */
    @PostMapping("/protected/bulk-access")
    public ResponseEntity<?> proxyBulkAccess(
            @RequestParam int count,
            @RequestParam(defaultValue = "5") int durationMinutes,
            HttpSession session) {

        String sessionId = session.getId();
        ContextState state = contextStates.getOrDefault(sessionId, new ContextState());

        if (state.getUserId() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Not authenticated"));
        }

        List<Map<String, Object>> results = new ArrayList<>();
        int successCount = 0;
        int blockedCount = 0;

        // 대량 접근 시뮬레이션
        for (int i = 0; i < count; i++) {
            String customerId = String.format("CUST%03d", i + 1);
            state.incrementRequestCount();
            state.addToHistory("BULK_ACCESS_" + customerId);

            try {
                Optional<CustomerData> data = protectableDataService.getCustomerData(customerId);
                if (data.isPresent()) {
                    successCount++;
                    results.add(Map.of(
                        "customerId", customerId,
                        "status", "accessed",
                        "timestamp", LocalDateTime.now()
                    ));
                }

                // 행동 이벤트 발행
                behaviorMonitor.publishBehaviorEvent(
                    state.getUserId(),
                    "BULK_DATA_ACCESS",
                    state.getCurrentIp(),
                    calculateRiskScore(state) + (i * 0.5) // 접근할수록 위험도 증가
                );

            } catch (SecurityException e) {
                blockedCount++;
                results.add(Map.of(
                    "customerId", customerId,
                    "status", "blocked",
                    "reason", e.getMessage()
                ));

                log.warn("Bulk access blocked at item {}: {}", i, e.getMessage());
                break; // 차단되면 중단
            }

            // 짧은 지연 (실제 공격 패턴 시뮬레이션)
            try {
                Thread.sleep(100); // 100ms 지연
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        log.info("Bulk access completed: user={}, success={}, blocked={}",
                state.getUserId(), successCount, blockedCount);

        return ResponseEntity.ok(Map.of(
            "status", "completed",
            "totalRequested", count,
            "successCount", successCount,
            "blockedCount", blockedCount,
            "results", results.subList(0, Math.min(10, results.size())), // 처음 10개만 반환
            "context", state
        ));
    }

    /**
     * 현재 컨텍스트 상태 조회
     */
    @GetMapping("/status")
    public ResponseEntity<?> getContextStatus(HttpSession session) {
        String sessionId = session.getId();
        ContextState state = contextStates.get(sessionId);

        if (state == null) {
            return ResponseEntity.ok(Map.of(
                "status", "no_context",
                "sessionId", sessionId
            ));
        }

        // Redis에서 현재 위협 점수 조회
        float threatScore = 0.0f;
        if (state.getUserId() != null) {
            threatScore = behaviorMonitor.getCurrentRiskScore(state.getUserId());
        }

        return ResponseEntity.ok(Map.of(
            "status", "active",
            "context", state,
            "threatScore", threatScore,
            "trustScore", 1.0f - (threatScore / 100.0f),
            "sessionId", sessionId,
            "requestCount", state.getRequestCount(),
            "lastActivity", state.getLastRequestTime()
        ));
    }

    /**
     * 컨텍스트 초기화
     */
    @PostMapping("/reset")
    public ResponseEntity<?> resetContext(HttpSession session) {
        String sessionId = session.getId();
        contextStates.remove(sessionId);

        log.info("Context reset for session: {}", sessionId);

        return ResponseEntity.ok(Map.of(
            "status", "reset",
            "sessionId", sessionId
        ));
    }

    /**
     * 빠른 연속 접근 시뮬레이션 (공격자 패턴)
     */
    private void simulateRapidAccess(ContextState state, String targetId) {
        // 5초 내에 10번 접근
        for (int i = 0; i < 10; i++) {
            behaviorMonitor.publishBehaviorEvent(
                state.getUserId(),
                "RAPID_ACCESS_ATTEMPT",
                state.getCurrentIp(),
                70.0 + i * 2.0 // 위험도 증가
            );

            try {
                Thread.sleep(500); // 500ms 간격
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 점진적 증가 패턴 (내부자 위협)
     */
    private void simulateGradualEscalation(ContextState state, String targetId) {
        // 점진적으로 접근 빈도 증가
        behaviorMonitor.publishBehaviorEvent(
            state.getUserId(),
            "GRADUAL_ESCALATION",
            state.getCurrentIp(),
            30.0 + state.getRequestCount() * 1.5
        );
    }

    /**
     * 다양한 공격 시나리오 실행
     * LoginAttackClient가 있으면 실제 공격 수행, 없으면 기존 시뮬레이션 사용
     */
    @PostMapping("/execute-attack")
    public ResponseEntity<?> executeAttackScenario(
            @RequestParam String attackType,
            @RequestParam(required = false) String targetUser,
            HttpSession session) {

        String sessionId = session.getId();
        ContextState state = contextStates.getOrDefault(sessionId, new ContextState());

        if (state.getUserId() == null && !attackType.equals("CREDENTIAL_STUFFING") && !attackType.equals("BRUTE_FORCE")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Not authenticated"));
        }

        Map<String, Object> result = new HashMap<>();
        result.put("attackType", attackType);
        result.put("timestamp", LocalDateTime.now());

        try {
            // LoginAttackClient가 있으면 실제 공격 수행
            if (loginAttackClient != null) {
                switch (attackType) {
                    case "BRUTE_FORCE":
                        // 실제 브루트포스 공격 수행
                        io.contexa.contexacore.simulation.client.LoginAttackClient.AttackResult bruteForceResult =
                            loginAttackClient.bruteForceAttack(targetUser != null ? targetUser : "admin");
                        result.put("realAttack", true);
                        result.put("attempts", bruteForceResult.getTotalAttempts());
                        result.put("success", bruteForceResult.isSuccessful());
                        break;

                    case "CREDENTIAL_STUFFING":
                        // 실제 크리덴셜 스터핑 공격 수행
                        io.contexa.contexacore.simulation.client.LoginAttackClient.AttackResult stuffingResult =
                            loginAttackClient.credentialStuffingAttack();
                        result.put("realAttack", true);
                        result.put("attempts", stuffingResult.getTotalAttempts());
                        result.put("successfulLogins", stuffingResult.getSuccessfulAttempts());
                        break;

                    case "SESSION_HIJACKING":
                        if (state.getUserId() != null) {
                            // 실제 세션 하이재킹 공격 수행
                            io.contexa.contexacore.simulation.client.LoginAttackClient.AttackResult hijackResult =
                                loginAttackClient.sessionHijackingAttack(state.getUserId(), "1234"); // 실제 비밀번호 필요
                            result.put("realAttack", true);
                            result.put("hijacked", hijackResult.isSuccessful());
                        } else {
                            result.putAll(simulateSessionHijacking(state));
                        }
                        break;

                    default:
                        // 다른 공격 타입은 기존 시뮬레이션 사용
                        executeSimulatedAttack(attackType, state, targetUser, result);
                        break;
                }
            } else {
                // LoginAttackClient가 없으면 기존 시뮬레이션 사용
                executeSimulatedAttack(attackType, state, targetUser, result);
            }

        } catch (Exception e) {
            log.error("Attack execution failed: {}", e.getMessage(), e);
            result.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }

        return ResponseEntity.ok(result);
    }

    private void executeSimulatedAttack(String attackType, ContextState state, String targetUser, Map<String, Object> result) {
        switch (attackType) {
            case "SESSION_HIJACKING":
                result.putAll(simulateSessionHijacking(state));
                break;
            case "IMPOSSIBLE_TRAVEL":
                result.putAll(simulateImpossibleTravel(state));
                break;
            case "CREDENTIAL_STUFFING":
                result.putAll(simulateCredentialStuffing(targetUser));
                break;
            case "PRIVILEGE_ESCALATION":
                result.putAll(simulatePrivilegeEscalation(state));
                break;
            case "API_ABUSE":
                result.putAll(simulateAPIAbuse(state));
                break;
            case "MFA_BYPASS":
                result.putAll(simulateMFABypass(state));
                break;
            default:
                result.put("error", "Unknown attack type: " + attackType);
        }
    }

    /**
     * 세션 하이재킹 시뮬레이션
     */
    private Map<String, Object> simulateSessionHijacking(ContextState state) {
        // 세션을 다른 IP에서 재사용
        String originalIp = state.getCurrentIp();
        String hijackedIp = simulationConfig.getAttackIps().getSessionHijacking().getHijacked();

        state.setCurrentIp(hijackedIp);
        state.addToHistory("SESSION_HIJACK_FROM_" + originalIp);

        // 행동 이벤트 발행
        behaviorMonitor.publishBehaviorEvent(
            state.getUserId(),
            "SESSION_HIJACKING_ATTEMPT",
            hijackedIp,
            85.0  // 높은 위험도
        );

        return Map.of(
            "scenario", "Session Hijacking",
            "originalIp", originalIp,
            "hijackedIp", hijackedIp,
            "detection", "IP change detected in active session"
        );
    }

    /**
     * Impossible Travel 시뮬레이션
     */
    private Map<String, Object> simulateImpossibleTravel(ContextState state) {
        List<Map<String, Object>> travelEvents = new ArrayList<>();

        // 서울에서 로그인
        String koreaIp = simulationConfig.getAttackIps().getImpossibleTravel().getKorea();
        state.setCurrentIp(koreaIp);
        travelEvents.add(Map.of(
            "location", simulationConfig.getLocations().get(koreaIp),
            "ip", state.getCurrentIp(),
            "time", LocalDateTime.now()
        ));

        // 5분 후 뉴욕에서 로그인
        String usaIp = simulationConfig.getAttackIps().getImpossibleTravel().getUsa();
        state.setCurrentIp(usaIp);
        travelEvents.add(Map.of(
            "location", simulationConfig.getLocations().get(usaIp),
            "ip", state.getCurrentIp(),
            "time", LocalDateTime.now().plusMinutes(5)
        ));

        // 거리는 설정에서 가져오기
        int distance = simulationConfig.getDistances().get("Seoul-NewYork");

        // 물리적으로 불가능한 이동
        behaviorMonitor.publishBehaviorEvent(
            state.getUserId(),
            "IMPOSSIBLE_TRAVEL_DETECTED",
            state.getCurrentIp(),
            simulationConfig.getRiskScores().getImpossibleTravel() * 100  // 위험도 설정값 사용
        );

        return Map.of(
            "scenario", "Impossible Travel",
            "travelEvents", travelEvents,
            "distance", distance + " km",
            "timeGap", "5 minutes",
            "physicallyPossible", false
        );
    }

    /**
     * Credential Stuffing 시뮬레이션
     */
    private Map<String, Object> simulateCredentialStuffing(String targetUser) {
        List<Map<String, String>> attempts = new ArrayList<>();

        // 설정 파일에서 credential stuffing 시도 목록 가져오기
        List<SimulationConfig.AttackPatterns.CredentialStuffing.Credential> credentials =
            simulationConfig.getAttackPatterns().getCredentialStuffing().getAttempts();

        for (SimulationConfig.AttackPatterns.CredentialStuffing.Credential cred : credentials) {
            String username = cred.getUsername();
            String password = cred.getPassword();

            attempts.add(Map.of(
                "username", username,
                "password", password,
                "result", username.equals("admin") && password.equals("1234") ? "SUCCESS" : "FAILED"
            ));

            // 각 시도마다 이벤트 발행 - 설정에서 의심스러운 IP 사용
            String suspiciousIp = simulationConfig.getAttackIps().getSuspicious().get(2); // 세 번째 의심스러운 IP 사용
            behaviorMonitor.publishBehaviorEvent(
                username,
                "CREDENTIAL_STUFFING_ATTEMPT",
                suspiciousIp,
                70.0
            );
        }

        long successCount = attempts.stream()
            .filter(a -> "SUCCESS".equals(a.get("result")))
            .count();

        return Map.of(
            "scenario", "Credential Stuffing",
            "attempts", attempts,
            "totalAttempts", attempts.size(),
            "successfulAttempts", successCount
        );
    }

    /**
     * 권한 상승 시뮬레이션 - 실제 권한 체계 반영
     */
    private Map<String, Object> simulatePrivilegeEscalation(ContextState state) {
        // 현재 사용자의 실제 권한 확인
        String currentUser = state.getUserId();
        String currentRole = getUserActualRole(currentUser);

        // 권한별 시도할 엔드포인트 - 설정 파일에서 가져오기
        Map<String, String> escalationTargets = new LinkedHashMap<>();
        SimulationConfig.AttackPatterns.PrivilegeEscalation.Endpoints endpoints =
            simulationConfig.getAttackPatterns().getPrivilegeEscalation().getEndpoints();

        // 현재 권한에 따라 다른 상승 시나리오
        switch (currentRole) {
            case "ROLE_DEVELOPER":
                // 개발자가 시도할 수 있는 권한 상승
                if (!endpoints.getFinance().isEmpty()) {
                    escalationTargets.put(endpoints.getFinance().get(0), "ROLE_FINANCE_MANAGER");
                }
                if (!endpoints.getInfrastructure().isEmpty()) {
                    escalationTargets.put(endpoints.getInfrastructure().get(0), "ROLE_OPERATOR");
                }
                if (!endpoints.getAdmin().isEmpty()) {
                    escalationTargets.put(endpoints.getAdmin().get(2), "ROLE_ADMIN"); // system-config
                }
                break;

            case "ROLE_OPERATOR":
                // 운영자가 시도할 수 있는 권한 상승
                if (!endpoints.getFinance().isEmpty()) {
                    escalationTargets.put(endpoints.getFinance().get(0), "ROLE_FINANCE_MANAGER");
                }
                if (!endpoints.getAdmin().isEmpty()) {
                    escalationTargets.put(endpoints.getAdmin().get(0), "ROLE_ADMIN"); // users
                }
                break;

            case "ROLE_FINANCE_MANAGER":
                // 재무 관리자가 시도할 수 있는 권한 상승
                if (!endpoints.getAdmin().isEmpty()) {
                    escalationTargets.put(endpoints.getAdmin().get(2), "ROLE_ADMIN"); // system-config
                    escalationTargets.put(endpoints.getAdmin().get(3), "ROLE_ADMIN"); // audit-logs
                }
                break;

            default:
                // 기본 사용자
                if (!endpoints.getFinance().isEmpty()) {
                    escalationTargets.put(endpoints.getFinance().get(0), "ROLE_FINANCE_MANAGER");
                }
                if (!endpoints.getAdmin().isEmpty()) {
                    escalationTargets.put(endpoints.getAdmin().get(0), "ROLE_ADMIN");
                }
                break;
        }

        List<Map<String, Object>> results = new ArrayList<>();

        for (Map.Entry<String, String> entry : escalationTargets.entrySet()) {
            String endpoint = entry.getKey();
            String requiredRole = entry.getValue();

            // 권한 상승 위험도 계산
            double riskScore = calculatePrivilegeEscalationRisk(currentRole, requiredRole);

            state.addToHistory("PRIVILEGE_ESCALATION_" + endpoint);

            results.add(Map.of(
                "endpoint", endpoint,
                "currentRole", currentRole,
                "requiredRole", requiredRole,
                "blocked", true,
                "riskScore", riskScore,
                "pattern", getEscalationPattern(currentRole, requiredRole)
            ));

            behaviorMonitor.publishBehaviorEvent(
                state.getUserId(),
                "PRIVILEGE_ESCALATION_ATTEMPT",
                state.getCurrentIp(),
                riskScore
            );
        }

        return Map.of(
            "scenario", "Privilege Escalation",
            "currentUser", currentUser,
            "currentRole", currentRole,
            "attempts", results,
            "detection", "Unauthorized privilege escalation attempts detected",
            "highestRisk", results.stream()
                .mapToDouble(m -> (Double) m.get("riskScore"))
                .max().orElse(0.0)
        );
    }

    /**
     * 사용자의 실제 권한 조회
     */
    private String getUserActualRole(String username) {
        Map<String, String> userRoles = Map.of(
            "admin", "ROLE_ADMIN",
            "dev_lead", "ROLE_LEAD_DEVELOPER",
            "dev_user", "ROLE_DEVELOPER",
            "op_user", "ROLE_OPERATOR",
            "finance_manager", "ROLE_FINANCE_MANAGER"
        );
        return userRoles.getOrDefault(username, "ROLE_USER");
    }

    /**
     * 권한 상승 위험도 계산
     */
    private double calculatePrivilegeEscalationRisk(String fromRole, String toRole) {
        // 권한 레벨 정의 (높을수록 더 많은 권한)
        Map<String, Integer> roleLevels = Map.of(
            "ROLE_ADMIN", 100,
            "ROLE_FINANCE_MANAGER", 80,
            "ROLE_OPERATOR", 60,
            "ROLE_LEAD_DEVELOPER", 50,
            "ROLE_DEVELOPER", 30,
            "ROLE_USER", 10
        );

        int fromLevel = roleLevels.getOrDefault(fromRole, 10);
        int toLevel = roleLevels.getOrDefault(toRole, 10);
        int levelDiff = toLevel - fromLevel;

        // 특수 케이스별 위험도 - 설정값 * 100을 사용하거나 계산된 값 사용
        if (fromRole.equals("ROLE_DEVELOPER") && toRole.equals("ROLE_FINANCE_MANAGER")) {
            // 개발자 -> 재무: 부서 간 권한 상승 (매우 위험)
            return 0.85;
        }
        if (fromRole.equals("ROLE_DEVELOPER") && toRole.equals("ROLE_ADMIN")) {
            // 개발자 -> 관리자: 극단적 권한 상승
            return 0.95;
        }
        if (fromRole.equals("ROLE_OPERATOR") && toRole.equals("ROLE_ADMIN")) {
            // 운영자 -> 관리자: 고위험
            return 0.90;
        }
        if (fromRole.equals("ROLE_FINANCE_MANAGER") && toRole.equals("ROLE_ADMIN")) {
            // 재무 -> 관리자: 위험
            return 0.80;
        }

        // 일반적인 위험도 계산
        double baseRisk = levelDiff / 100.0;
        return Math.min(1.0, baseRisk + 0.3);
    }

    /**
     * 권한 상승 패턴 분류
     */
    private String getEscalationPattern(String fromRole, String toRole) {
        Map<String, Integer> roleLevels = Map.of(
            "ROLE_ADMIN", 100,
            "ROLE_FINANCE_MANAGER", 80,
            "ROLE_OPERATOR", 60,
            "ROLE_LEAD_DEVELOPER", 50,
            "ROLE_DEVELOPER", 30,
            "ROLE_USER", 10
        );

        int levelDiff = roleLevels.getOrDefault(toRole, 10) - roleLevels.getOrDefault(fromRole, 10);

        // 부서 간 이동 체크
        boolean crossDepartment =
            (fromRole.contains("DEVELOPER") && toRole.contains("FINANCE")) ||
            (fromRole.contains("OPERATOR") && toRole.contains("FINANCE")) ||
            (fromRole.contains("FINANCE") && toRole.contains("DEVELOPER"));

        if (crossDepartment) {
            return "CROSS_DEPARTMENT_ESCALATION";
        }
        if (levelDiff > 50) {
            return "EXTREME_PRIVILEGE_JUMP";
        }
        if (levelDiff > 30) {
            return "HIGH_PRIVILEGE_JUMP";
        }
        if (toRole.equals("ROLE_ADMIN")) {
            return "ADMIN_ACCESS_ATTEMPT";
        }
        return "MODERATE_PRIVILEGE_JUMP";
    }

    /**
     * API Abuse 시뮬레이션
     */
    private Map<String, Object> simulateAPIAbuse(ContextState state) {
        // 설정에서 API 남용 패턴 가져오기
        SimulationConfig.AttackPatterns.ApiAbuse apiAbuse =
            simulationConfig.getAttackPatterns().getApiAbuse();

        int requestCount = apiAbuse.getRateLimits().getAbusive();  // 설정에서 가져온 남용 요청 수
        int timeWindowSeconds = apiAbuse.getTimeWindow();
        int normalRate = apiAbuse.getRateLimits().getNormal();

        // API 남용 패턴
        for (int i = 0; i < requestCount; i++) {
            state.incrementRequestCount();
            state.addToHistory("API_CALL_" + i);
        }

        double requestsPerSecond = requestCount / (double) timeWindowSeconds;

        behaviorMonitor.publishBehaviorEvent(
            state.getUserId(),
            "API_ABUSE_DETECTED",
            state.getCurrentIp(),
            Math.min(requestsPerSecond * 10, 100)  // 요청률 기반 위험도
        );

        return Map.of(
            "scenario", "API Abuse",
            "requestCount", requestCount,
            "timeWindow", timeWindowSeconds + " seconds",
            "requestsPerSecond", requestsPerSecond,
            "rateLimit", normalRate + " req/s",
            "violated", requestsPerSecond > normalRate
        );
    }

    /**
     * MFA Bypass 시뮬레이션
     */
    private Map<String, Object> simulateMFABypass(ContextState state) {
        // 설정에서 MFA bypass 방법 가져오기
        List<String> bypassMethods = simulationConfig.getAttackPatterns()
            .getMfaBypass().getMethods();

        List<Map<String, String>> bypassAttempts = new ArrayList<>();
        for (String method : bypassMethods) {
            bypassAttempts.add(Map.of(
                "method", method,
                "success", "blocked"
            ));

            behaviorMonitor.publishBehaviorEvent(
                state.getUserId(),
                "MFA_BYPASS_ATTEMPT_" + method.toUpperCase().replace(" ", "_"),
                state.getCurrentIp(),
                90.0  // MFA 우회는 매우 위험
            );
        }

        return Map.of(
            "scenario", "MFA Bypass",
            "attempts", bypassAttempts,
            "allBlocked", true,
            "detection", "Multiple MFA bypass techniques attempted"
        );
    }

    /**
     * 컨텍스트 기반 위험 점수 계산
     */
    private double calculateRiskScore(ContextState state) {
        double score = 0.0;
        SimulationConfig.RiskScores riskScores = simulationConfig.getRiskScores();

        // IP 기반 위험도 - 설정에서 의심스러운 IP 확인
        boolean isSuspiciousIp = simulationConfig.getAttackIps().getSuspicious()
            .contains(state.getCurrentIp());
        if (isSuspiciousIp) {
            score += riskScores.getIpChange() * 100;
        } else if (!state.getCurrentIp().startsWith("192.168")) {
            score += (riskScores.getIpChange() * 100) / 2; // 외부 IP
        }

        // 시간 기반 위험도 - 설정에서 정상/비정상 시간 확인
        LocalTime time = state.getSimulatedTime();
        SimulationConfig.Timezones.NormalHours normalHours = simulationConfig.getTimezones().getNormalHours();
        SimulationConfig.Timezones.SuspiciousHours suspiciousHours = simulationConfig.getTimezones().getSuspiciousHours();

        if (time.getHour() < normalHours.getStart() || time.getHour() >= normalHours.getEnd()) {
            // 비정상 시간대
            if (suspiciousHours.getEarlyMorning().contains(time.getHour()) ||
                suspiciousHours.getLateNight().contains(time.getHour())) {
                score += riskScores.getOffHours() * 100;
            }
        }

        // User-Agent 기반 위험도 - 설정에서 의심스러운 UA 확인
        boolean isSuspiciousAgent = simulationConfig.getUserAgents().getSuspicious().stream()
            .anyMatch(ua -> state.getCurrentUserAgent().toLowerCase().contains(ua.toLowerCase()));
        if (isSuspiciousAgent) {
            score += riskScores.getSuspiciousAgent() * 100;
        }

        // 언어 기반 위험도
        if ("ru-RU".equals(state.getCurrentLanguage()) || "zh-CN".equals(state.getCurrentLanguage())) {
            score += riskScores.getLocationChange() * 100 / 2; // 의심스러운 언어
        }

        // 요청 빈도 기반 위험도
        if (state.getRequestCount() > 50) {
            score += riskScores.getRepeatedAttempts() * 100; // 과도한 요청
        } else if (state.getRequestCount() > 20) {
            score += (riskScores.getRepeatedAttempts() * 100) / 2;
        }

        // 접근 패턴 기반 위험도
        if (state.getAccessHistory().size() > 10) {
            long bulkAccessCount = state.getAccessHistory().stream()
                    .filter(h -> h.contains("BULK"))
                    .count();
            if (bulkAccessCount > 5) {
                score += 20.0; // 대량 접근 패턴
            }
        }

        return Math.min(score, 100.0); // 최대 100
    }

    /**
     * 인증 컨텍스트 판단
     */
    private String determineAuthContext(ContextState state) {
        // IP 기반 판단
        boolean isSuspiciousIp = simulationConfig.getAttackIps().getSuspicious()
            .contains(state.getCurrentIp());
        boolean isTorIp = state.getCurrentIp() != null && state.getCurrentIp().startsWith("185.220");

        // User-Agent 기반 판단
        boolean isSuspiciousAgent = simulationConfig.getUserAgents().getSuspicious().stream()
            .anyMatch(ua -> state.getCurrentUserAgent().toLowerCase().contains(ua.toLowerCase()));

        // 언어 기반 판단
        boolean isSuspiciousLang = "ru-RU".equals(state.getCurrentLanguage()) ||
                                   "zh-CN".equals(state.getCurrentLanguage());

        // 시간 기반 판단
        LocalTime time = state.getSimulatedTime();
        boolean isOffHours = time.getHour() < 7 || time.getHour() >= 22;

        if (isTorIp || (isSuspiciousIp && isSuspiciousAgent)) {
            return "공격자";
        } else if (isOffHours && state.getRequestCount() > 20) {
            return "내부자 위협";
        } else if (isSuspiciousIp || isSuspiciousAgent || isSuspiciousLang) {
            return "의심";
        } else {
            return "정상";
        }
    }

    /**
     * 이벤트 로그 추가 헬퍼 메서드
     */
    private void addEventLog(String message, String level) {
        log.info("[{}] {}", level.toUpperCase(), message);
    }

    /**
     * 모든 활성 컨텍스트 조회 (관리용)
     */
    @GetMapping("/admin/contexts")
    public ResponseEntity<?> getAllContexts() {
        return ResponseEntity.ok(Map.of(
            "activeContexts", contextStates.size(),
            "contexts", contextStates
        ));
    }

    public static class ContextState {
        private String currentIp;
        private String currentUserAgent;
        private String currentLanguage;
        private LocalTime simulatedTime;
        private String sessionId;
        private String userId;
        private int requestCount;
        private LocalDateTime lastRequestTime;
        private List<String> accessHistory;

        public ContextState() {
            this.currentIp = "127.0.0.1";
            this.currentUserAgent = "Mozilla/5.0";
            this.currentLanguage = "en-US";
            this.simulatedTime = LocalTime.now();
            this.requestCount = 0;
            this.accessHistory = new ArrayList<>();
            this.lastRequestTime = LocalDateTime.now();
        }

        // Getters and setters
        public String getCurrentIp() { return currentIp; }
        public void setCurrentIp(String currentIp) { this.currentIp = currentIp; }

        public String getCurrentUserAgent() { return currentUserAgent; }
        public void setCurrentUserAgent(String currentUserAgent) { this.currentUserAgent = currentUserAgent; }

        public String getCurrentLanguage() { return currentLanguage; }
        public void setCurrentLanguage(String currentLanguage) { this.currentLanguage = currentLanguage; }

        public LocalTime getSimulatedTime() { return simulatedTime; }
        public void setSimulatedTime(LocalTime simulatedTime) { this.simulatedTime = simulatedTime; }

        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }

        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public int getRequestCount() { return requestCount; }
        public void incrementRequestCount() { this.requestCount++; }

        public LocalDateTime getLastRequestTime() { return lastRequestTime; }
        public void setLastRequestTime(LocalDateTime lastRequestTime) { this.lastRequestTime = lastRequestTime; }

        public List<String> getAccessHistory() { return accessHistory; }
        public void addToHistory(String access) {
            this.accessHistory.add(access);
            if (this.accessHistory.size() > 100) {
                this.accessHistory.remove(0);
            }
        }
    }
}