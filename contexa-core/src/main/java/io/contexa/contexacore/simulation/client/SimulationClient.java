package io.contexa.contexacore.simulation.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.support.RestTemplateAdapter;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 시뮬레이션 HTTP 클라이언트 기본 클래스
 * 
 * 실제 공격자처럼 HTTP 요청을 생성하고 실행하는 기본 클라이언트입니다.
 * 세션 관리, 쿠키 처리, 헤더 조작 등의 기능을 제공합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Component
public class SimulationClient {
    
    private final String baseUrl;
    private final int timeoutSeconds;
    private final int retryCount;
    private final boolean followRedirects;
    
    private final RestTemplate restTemplate;
    private final Map<String, String> sessionStorage = new ConcurrentHashMap<>();
    private final Map<String, List<String>> cookieStore = new ConcurrentHashMap<>();
    private String currentSessionId;
    private String currentAuthToken;
    
    // 다양한 User-Agent 목록
    private static final List<String> USER_AGENTS = Arrays.asList(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "Mozilla/5.0 (Android 14; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
        "python-requests/2.31.0",
        "curl/8.4.0",
        "PostmanRuntime/7.35.0"
    );
    
    // IP 위치 시뮬레이션용 데이터
    private static final Map<String, String> LOCATION_IPS = new HashMap<>();
    static {
        LOCATION_IPS.put("Seoul", generateStaticRandomIP());
        LOCATION_IPS.put("NewYork", generateStaticRandomIP());
        LOCATION_IPS.put("London", generateStaticRandomIP());
        LOCATION_IPS.put("Tokyo", "203.0.113.88");  // Keep test-net IP
        LOCATION_IPS.put("Moscow", generateStaticRandomIP());
        LOCATION_IPS.put("Beijing", generateStaticRandomIP());
        LOCATION_IPS.put("Sydney", "198.51.100.214"); // Keep test-net IP
        LOCATION_IPS.put("SaoPaulo", generateStaticRandomIP());
        LOCATION_IPS.put("Mumbai", generateStaticRandomIP());
        LOCATION_IPS.put("Cairo", generateStaticRandomIP());
    }
    
    public SimulationClient(
            RestTemplate restTemplate,
            @Value("${simulation.client.base-url:http://localhost:8080}") String baseUrl,
            @Value("${simulation.client.timeout:30}") int timeoutSeconds,
            @Value("${simulation.client.retry-count:3}") int retryCount,
            @Value("${simulation.client.follow-redirects:true}") boolean followRedirects) {
        
        this.baseUrl = baseUrl;
        this.timeoutSeconds = timeoutSeconds;
        this.retryCount = retryCount;
        this.followRedirects = followRedirects;
        this.restTemplate = restTemplate;
        
        log.info("SimulationClient 초기화 - BaseURL: {}, Timeout: {}s", baseUrl, timeoutSeconds);
    }
    
    /**
     * 공격 실행 헬퍼 메소드
     * executeAttack 호출을 post로 변환
     */
    public ResponseEntity<String> executeAttack(String endpoint, Map<String, ?> params) {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Attack-Simulation", "true");
        return post(endpoint, params, headers);
    }

    /**
     * 인증된 요청 헬퍼 메소드
     */
    public ResponseEntity<String> requestWithAuth(String endpoint, String token, String method) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + token);

        if ("GET".equalsIgnoreCase(method)) {
            return get(endpoint, new HashMap<>(), headers);
        } else {
            return post(endpoint, null, headers);
        }
    }

    /**
     * GET 요청 실행
     */
    public ResponseEntity<String> get(String path, Map<String, String> params, Map<String, String> headers) {
        URI uri = buildUri(path, params);
        HttpHeaders httpHeaders = buildHeaders(headers);
        HttpEntity<Void> entity = new HttpEntity<>(httpHeaders);
        
        log.debug("GET 요청: {}", uri);
        return executeRequest(uri, HttpMethod.GET, entity, String.class);
    }
    
    /**
     * POST 요청 실행
     */
    public ResponseEntity<String> post(String path, Object body, Map<String, String> headers) {
        URI uri = buildUri(path, null);
        HttpHeaders httpHeaders = buildHeaders(headers);
        HttpEntity<Object> entity = new HttpEntity<>(body, httpHeaders);
        
        log.debug("POST 요청: {}", uri);
        return executeRequest(uri, HttpMethod.POST, entity, String.class);
    }
    
    /**
     * PUT 요청 실행
     */
    public ResponseEntity<String> put(String path, Object body, Map<String, String> headers) {
        URI uri = buildUri(path, null);
        HttpHeaders httpHeaders = buildHeaders(headers);
        HttpEntity<Object> entity = new HttpEntity<>(body, httpHeaders);
        
        log.debug("PUT 요청: {}", uri);
        return executeRequest(uri, HttpMethod.PUT, entity, String.class);
    }
    
    /**
     * DELETE 요청 실행
     */
    public ResponseEntity<String> delete(String path, Map<String, String> headers) {
        URI uri = buildUri(path, null);
        HttpHeaders httpHeaders = buildHeaders(headers);
        HttpEntity<Void> entity = new HttpEntity<>(httpHeaders);
        
        log.debug("DELETE 요청: {}", uri);
        return executeRequest(uri, HttpMethod.DELETE, entity, String.class);
    }
    
    /**
     * 로그인 요청 (폼 방식)
     */
    public ResponseEntity<String> login(String username, String password) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", username);
        formData.add("password", password);
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("User-Agent", getRandomUserAgent());
        
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formData, headers);
        
        log.info("로그인 시도: username={}", username);
        ResponseEntity<String> response = restTemplate.exchange(
            baseUrl + "/api/auth/login",
            HttpMethod.POST,
            entity,
            String.class
        );
        
        // 세션/토큰 저장
        extractAndStoreSession(response);
        extractAndStoreAuthToken(response);
        
        return response;
    }
    
    /**
     * 로그인 요청 - 실제 Spring Security /login 엔드포인트 사용
     */
    public ResponseEntity<String> loginJson(String username, String password) {
        // Spring Security는 form 데이터를 기대하므로 form-urlencoded 사용
        MultiValueMap<String, String> loginData = new LinkedMultiValueMap<>();
        loginData.add("username", username);
        loginData.add("password", password);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("User-Agent", getRandomUserAgent());

        // 공격 시뮬레이션을 위한 다양한 헤더 추가
        if (new Random().nextBoolean()) {
            // 50% 확률로 의심스러운 IP 헤더 추가
            String suspiciousIp = generateRandomIP();
            headers.set("X-Forwarded-For", suspiciousIp);
            headers.set("X-Real-IP", suspiciousIp);
        }

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(loginData, headers);

        log.info("실제 Spring Security 로그인 시도: username={}, endpoint=/login", username);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                baseUrl + "/login",  // 실제 Spring Security 엔드포인트
                HttpMethod.POST,
                entity,
                String.class
            );

            extractAndStoreSession(response);
            extractAndStoreAuthToken(response);

            // Spring Security는 성공 시 302 redirect를 반환
            if (response.getStatusCode() == HttpStatus.FOUND ||
                response.getStatusCode() == HttpStatus.OK) {
                log.info("로그인 성공: username={}, status={}", username, response.getStatusCode());
            } else {
                log.warn("로그인 실패: username={}, status={}", username, response.getStatusCode());
            }

            return response;
        } catch (Exception e) {
            log.error("로그인 요청 실패: username={}, error={}", username, e.getMessage());
            // 실패 시에도 ResponseEntity 반환
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed: " + e.getMessage());
        }
    }
    
    /**
     * 특정 위치에서 요청 시뮬레이션
     */
    public ResponseEntity<String> requestFromLocation(String path, String location, HttpMethod method, Object body) {
        String locationIp = LOCATION_IPS.getOrDefault(location, LOCATION_IPS.get("Seoul"));
        
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Forwarded-For", locationIp);
        headers.put("X-Real-IP", locationIp);
        headers.put("X-Originating-IP", locationIp);
        
        log.info("위치 시뮬레이션: {} (IP: {})", location, locationIp);
        
        if (method == HttpMethod.GET) {
            return get(path, null, headers);
        } else if (method == HttpMethod.POST) {
            return post(path, body, headers);
        } else {
            throw new IllegalArgumentException("Unsupported method: " + method);
        }
    }
    
    /**
     * 다양한 User-Agent로 요청
     */
    public ResponseEntity<String> requestWithUserAgent(String path, String userAgent) {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", userAgent);
        
        log.info("User-Agent 변경: {}", userAgent);
        return get(path, null, headers);
    }
    
    /**
     * 세션 하이재킹 시뮬레이션
     */
    public ResponseEntity<String> requestWithStolenSession(String path, String stolenSessionId) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Cookie", "JSESSIONID=" + stolenSessionId);
        
        log.warn("세션 하이재킹 시도: {}", stolenSessionId);
        return get(path, null, headers);
    }
    
    /**
     * 토큰 조작 시뮬레이션
     */
    public ResponseEntity<String> requestWithManipulatedToken(String path, String manipulatedToken) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + manipulatedToken);
        
        log.warn("토큰 조작 시도: {}", manipulatedToken);
        return get(path, null, headers);
    }
    
    /**
     * 대량 요청 생성 (DDoS 시뮬레이션용)
     */
    public List<ResponseEntity<String>> bulkRequests(String path, int count, int delayMs) {
        List<ResponseEntity<String>> responses = new ArrayList<>();
        
        log.warn("대량 요청 시작: {} 건", count);
        for (int i = 0; i < count; i++) {
            try {
                ResponseEntity<String> response = get(path, null, null);
                responses.add(response);
                
                if (delayMs > 0 && i < count - 1) {
                    Thread.sleep(delayMs);
                }
            } catch (Exception e) {
                log.error("대량 요청 중 오류 ({}번째): {}", i + 1, e.getMessage());
            }
        }
        
        return responses;
    }
    
    // === Helper Methods ===
    
    private URI buildUri(String path, Map<String, String> params) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl + path);
        
        if (params != null && !params.isEmpty()) {
            params.forEach(builder::queryParam);
        }
        
        return builder.build().toUri();
    }
    
    private HttpHeaders buildHeaders(Map<String, String> customHeaders) {
        HttpHeaders headers = new HttpHeaders();
        
        // 기본 헤더 설정
        headers.set("User-Agent", getRandomUserAgent());
        headers.set("Accept", "application/json, text/plain, */*");
        headers.set("Accept-Language", "ko-KR,ko;q=0.9,en;q=0.8");
        
        // 세션/인증 정보 추가
        if (currentSessionId != null) {
            headers.set("Cookie", "JSESSIONID=" + currentSessionId);
        }
        if (currentAuthToken != null) {
            headers.set("Authorization", "Bearer " + currentAuthToken);
        }
        
        // 커스텀 헤더 추가
        if (customHeaders != null) {
            customHeaders.forEach(headers::set);
        }
        
        return headers;
    }
    
    private <T> ResponseEntity<T> executeRequest(URI uri, HttpMethod method, HttpEntity<?> entity, Class<T> responseType) {
        int attempts = 0;
        Exception lastException = null;
        
        while (attempts < retryCount) {
            try {
                ResponseEntity<T> response = restTemplate.exchange(uri, method, entity, responseType);
                log.debug("요청 성공: {} {} - Status: {}", method, uri, response.getStatusCode());
                return response;
            } catch (Exception e) {
                attempts++;
                lastException = e;
                log.warn("요청 실패 (시도 {}/{}): {}", attempts, retryCount, e.getMessage());
                
                if (attempts < retryCount) {
                    try {
                        Thread.sleep(1000 * attempts); // 지수 백오프
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
        
        log.error("요청 최종 실패: {} {}", method, uri, lastException);
        throw new RuntimeException("Request failed after " + retryCount + " attempts", lastException);
    }
    
    private void extractAndStoreSession(ResponseEntity<String> response) {
        List<String> cookies = response.getHeaders().get(HttpHeaders.SET_COOKIE);
        if (cookies != null) {
            for (String cookie : cookies) {
                if (cookie.startsWith("JSESSIONID=")) {
                    currentSessionId = cookie.split(";")[0].substring(11);
                    log.info("세션 ID 저장: {}", currentSessionId);
                    sessionStorage.put("JSESSIONID", currentSessionId);
                }
            }
        }
    }
    
    private void extractAndStoreAuthToken(ResponseEntity<String> response) {
        String authHeader = response.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            currentAuthToken = authHeader.substring(7);
            log.info("인증 토큰 저장: {}", currentAuthToken.substring(0, Math.min(20, currentAuthToken.length())) + "...");
            sessionStorage.put("authToken", currentAuthToken);
        }
        
        // Body에서 토큰 추출 시도 (JSON 응답인 경우)
        String body = response.getBody();
        if (body != null && body.contains("\"token\"")) {
            try {
                int start = body.indexOf("\"token\":\"") + 9;
                int end = body.indexOf("\"", start);
                if (start > 8 && end > start) {
                    currentAuthToken = body.substring(start, end);
                    log.info("Body에서 토큰 추출: {}", currentAuthToken.substring(0, Math.min(20, currentAuthToken.length())) + "...");
                    sessionStorage.put("authToken", currentAuthToken);
                }
            } catch (Exception e) {
                log.debug("Body에서 토큰 추출 실패: {}", e.getMessage());
            }
        }
    }
    
    private String getRandomUserAgent() {
        return USER_AGENTS.get(new Random().nextInt(USER_AGENTS.size()));
    }
    
    private ClientHttpRequestInterceptor createLoggingInterceptor() {
        return (request, body, execution) -> {
            log.debug(">>> Request: {} {}", request.getMethod(), request.getURI());
            log.debug(">>> Headers: {}", request.getHeaders());
            
            var response = execution.execute(request, body);
            
            log.debug("<<< Response: {}", response.getStatusCode());
            log.debug("<<< Headers: {}", response.getHeaders());
            
            return response;
        };
    }
    
    // === Getter/Setter ===
    
    public String getCurrentSessionId() {
        return currentSessionId;
    }
    
    public String getCurrentAuthToken() {
        return currentAuthToken;
    }
    
    public void clearSession() {
        currentSessionId = null;
        currentAuthToken = null;
        sessionStorage.clear();
        cookieStore.clear();
        log.info("세션 정보 초기화");
    }
    
    public String getBaseUrl() {
        return baseUrl;
    }
    
    public Map<String, String> getSessionStorage() {
        return new HashMap<>(sessionStorage);
    }

    private static String generateStaticRandomIP() {
        Random random = new Random();
        int a = random.nextInt(256);
        int b = random.nextInt(256);
        int c = random.nextInt(256);
        int d = random.nextInt(256);
        return String.format("%d.%d.%d.%d", a, b, c, d);
    }

    private String generateRandomIP() {
        return generateStaticRandomIP();
    }
}