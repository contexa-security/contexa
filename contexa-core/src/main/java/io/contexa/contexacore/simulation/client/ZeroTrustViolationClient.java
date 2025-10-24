package io.contexa.contexacore.simulation.client;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Zero Trust 위반 시뮬레이션 클라이언트
 * 
 * Zero Trust 보안 모델 위반 시나리오를 시뮬레이션합니다.
 * Impossible Travel, Device Trust, Abnormal Behavior, Context-based violations 등을 포함합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ZeroTrustViolationClient {
    
    private final SimulationClient simulationClient;
    
    @Value("${simulation.attack.zerotrust.delay-ms:500}")
    private int attackDelayMs;
    
    // 전 세계 주요 도시 위치 정보
    private static final Map<String, LocationInfo> LOCATIONS = new HashMap<>();
    static {
        LOCATIONS.put("Seoul", new LocationInfo("Seoul", "Asia/Seoul", 37.5665, 126.9780, "211.234.100.50"));
        LOCATIONS.put("NewYork", new LocationInfo("New York", "America/New_York", 40.7128, -74.0060, "72.229.28.185"));
        LOCATIONS.put("London", new LocationInfo("London", "Europe/London", 51.5074, -0.1278, "81.2.69.142"));
        LOCATIONS.put("Tokyo", new LocationInfo("Tokyo", "Asia/Tokyo", 35.6762, 139.6503, "202.32.120.88"));
        LOCATIONS.put("Moscow", new LocationInfo("Moscow", "Europe/Moscow", 55.7558, 37.6173, "95.173.128.90"));
        LOCATIONS.put("Sydney", new LocationInfo("Sydney", "Australia/Sydney", -33.8688, 151.2093, "203.2.218.214"));
        LOCATIONS.put("Dubai", new LocationInfo("Dubai", "Asia/Dubai", 25.2048, 55.2708, "195.229.110.166"));
        LOCATIONS.put("Singapore", new LocationInfo("Singapore", "Asia/Singapore", 1.3521, 103.8198, "203.127.21.88"));
        LOCATIONS.put("Berlin", new LocationInfo("Berlin", "Europe/Berlin", 52.5200, 13.4050, "46.30.212.88"));
        LOCATIONS.put("Toronto", new LocationInfo("Toronto", "America/Toronto", 43.6532, -79.3832, "104.36.177.88"));
    }
    
    // 디바이스 정보
    private static final List<DeviceInfo> DEVICES = Arrays.asList(
        new DeviceInfo("Windows-Desktop-01", "Windows 10", "Chrome 120", "DESKTOP"),
        new DeviceInfo("MacBook-Pro-15", "macOS 14.0", "Safari 17", "LAPTOP"),
        new DeviceInfo("iPhone-14-Pro", "iOS 17.0", "Safari Mobile", "MOBILE"),
        new DeviceInfo("Android-Pixel-7", "Android 14", "Chrome Mobile", "MOBILE"),
        new DeviceInfo("iPad-Pro-2023", "iPadOS 17", "Safari Mobile", "TABLET"),
        new DeviceInfo("Linux-Server", "Ubuntu 22.04", "curl/8.0", "SERVER"),
        new DeviceInfo("Unknown-Device", "Unknown OS", "Unknown Browser", "UNKNOWN")
    );
    
    // 위험한 IP 범위들
    private static final List<String> RISKY_IP_RANGES = Arrays.asList(
        "45.142.120.",  // Known malicious range
        "185.220.100.", // Tor exit node
        "195.154.173.", // VPN provider
        "104.248.63.",  // Cloud provider abuse
        "167.99.88."    // Compromised servers
    );
    
    /**
     * Impossible Travel 공격 시뮬레이션
     */
    public AttackResult impossibleTravelAttack(String username, String password) {
        log.warn("=== Impossible Travel 공격 시작 ===");
        AttackResult result = new AttackResult("Impossible Travel Attack");
        
        try {
            // 1. 서울에서 정상 로그인
            LocationInfo seoul = LOCATIONS.get("Seoul");
            log.info("1단계: {}에서 정상 로그인", seoul.city);
            
            Map<String, String> seoulHeaders = createLocationHeaders(seoul);
            simulationClient.clearSession();
            ResponseEntity<String> seoulLogin = loginFromLocation(username, password, seoul);
            result.addAttempt("Login from " + seoul.city, 
                seoulLogin.getStatusCode() == HttpStatus.OK, seoulLogin);
            
            if (seoulLogin.getStatusCode() != HttpStatus.OK) {
                log.error("초기 로그인 실패");
                result.addError("Initial login failed");
                return result;
            }
            
            // 정상 활동 시뮬레이션
            Thread.sleep(2000);
            simulationClient.requestFromLocation("/api/user/profile", "Seoul", HttpMethod.GET, null);
            
            // 2. 5분 후 뉴욕에서 로그인 시도 (물리적으로 불가능)
            Thread.sleep(5000); // 5초 후
            LocationInfo newYork = LOCATIONS.get("NewYork");
            log.warn("2단계: 5초 후 {}에서 로그인 시도 (불가능한 이동)", newYork.city);
            
            ResponseEntity<String> newYorkLogin = loginFromLocation(username, password, newYork);
            result.addAttempt("Impossible Travel to " + newYork.city, 
                newYorkLogin.getStatusCode() == HttpStatus.OK, newYorkLogin);
            
            if (newYorkLogin.getStatusCode() == HttpStatus.OK) {
                log.error("!!! Impossible Travel 공격 성공: 서울 → 뉴욕 (5초)");
                result.setSuccessful(true);
            }
            
            // 3. 연속적인 불가능한 이동
            Thread.sleep(3000);
            LocationInfo london = LOCATIONS.get("London");
            log.warn("3단계: 3초 후 {}에서 접근 시도", london.city);
            
            ResponseEntity<String> londonAccess = accessFromLocation(
                "/api/user/sensitive-data", london);
            result.addAttempt("Multiple Impossible Travels", 
                londonAccess.getStatusCode() == HttpStatus.OK, londonAccess);
            
            // 4. 동시 다발적 위치에서 접근
            log.warn("4단계: 전 세계 동시 접근 시도");
            List<CompletableFuture<ResponseEntity<String>>> futures = new ArrayList<>();
            
            for (String city : Arrays.asList("Tokyo", "Moscow", "Sydney", "Dubai")) {
                CompletableFuture<ResponseEntity<String>> future = CompletableFuture.supplyAsync(() -> {
                    try {
                        return accessFromLocation("/api/user/data", LOCATIONS.get(city));
                    } catch (Exception e) {
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
                    }
                });
                futures.add(future);
            }
            
            for (CompletableFuture<ResponseEntity<String>> future : futures) {
                ResponseEntity<String> response = future.get(10, TimeUnit.SECONDS);
                if (response.getStatusCode() == HttpStatus.OK) {
                    log.error("!!! 동시 다발 위치 접근 성공");
                    result.setSuccessful(true);
                }
            }
            
        } catch (Exception e) {
            log.error("Impossible Travel 공격 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== Impossible Travel 공격 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    /**
     * Device Trust 위반 시뮬레이션
     */
    public AttackResult deviceTrustViolation(String username, String password) {
        log.warn("=== Device Trust 위반 시작 ===");
        AttackResult result = new AttackResult("Device Trust Violation");
        
        try {
            // 1. 등록된 디바이스로 정상 로그인
            DeviceInfo trustedDevice = DEVICES.get(0); // Windows Desktop
            log.info("1단계: 신뢰된 디바이스로 로그인: {}", trustedDevice.deviceId);
            
            Map<String, String> trustedHeaders = createDeviceHeaders(trustedDevice);
            ResponseEntity<String> trustedLogin = loginWithHeaders(username, password, trustedHeaders);
            result.addAttempt("Trusted Device Login", 
                trustedLogin.getStatusCode() == HttpStatus.OK, trustedLogin);
            
            // 2. 등록되지 않은 디바이스로 접근
            Thread.sleep(2000);
            DeviceInfo unknownDevice = DEVICES.get(DEVICES.size() - 1); // Unknown Device
            log.warn("2단계: 알 수 없는 디바이스로 접근: {}", unknownDevice.deviceId);
            
            Map<String, String> unknownHeaders = createDeviceHeaders(unknownDevice);
            ResponseEntity<String> unknownAccess = simulationClient.get(
                "/api/user/profile", null, unknownHeaders);
            result.addAttempt("Unknown Device Access", 
                unknownAccess.getStatusCode() == HttpStatus.OK, unknownAccess);
            
            if (unknownAccess.getStatusCode() == HttpStatus.OK) {
                log.error("!!! Unknown Device 접근 성공");
                result.setSuccessful(true);
            }
            
            // 3. 디바이스 정보 빈번한 변경
            log.warn("3단계: 디바이스 정보 빈번한 변경");
            for (int i = 0; i < 5; i++) {
                DeviceInfo randomDevice = DEVICES.get(ThreadLocalRandom.current().nextInt(DEVICES.size()));
                Map<String, String> headers = createDeviceHeaders(randomDevice);
                
                ResponseEntity<String> response = simulationClient.get(
                    "/api/user/data", null, headers);
                result.addAttempt("Device Switch #" + (i+1) + ": " + randomDevice.deviceId, 
                    response.getStatusCode() == HttpStatus.OK, response);
                
                Thread.sleep(attackDelayMs);
            }
            
            // 4. Jailbroken/Rooted 디바이스
            log.warn("4단계: Jailbroken/Rooted 디바이스 시뮬레이션");
            Map<String, String> jailbrokenHeaders = new HashMap<>();
            jailbrokenHeaders.put("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Jailbroken");
            jailbrokenHeaders.put("X-Device-Jailbroken", "true");
            jailbrokenHeaders.put("X-Device-Rooted", "true");
            
            ResponseEntity<String> jailbrokenResponse = simulationClient.get(
                "/api/user/sensitive", null, jailbrokenHeaders);
            result.addAttempt("Jailbroken Device Access", 
                jailbrokenResponse.getStatusCode() == HttpStatus.OK, jailbrokenResponse);
            
            // 5. 가상 머신/에뮬레이터에서 접근
            log.warn("5단계: 가상 머신/에뮬레이터 접근");
            Map<String, String> vmHeaders = new HashMap<>();
            vmHeaders.put("User-Agent", "Android SDK built for x86");
            vmHeaders.put("X-Device-Type", "EMULATOR");
            vmHeaders.put("X-VM-Detection", "VirtualBox");
            
            ResponseEntity<String> vmResponse = simulationClient.get(
                "/api/user/profile", null, vmHeaders);
            result.addAttempt("Virtual Machine Access", 
                vmResponse.getStatusCode() == HttpStatus.OK, vmResponse);
            
        } catch (Exception e) {
            log.error("Device Trust 위반 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== Device Trust 위반 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    /**
     * Abnormal Behavior Pattern 시뮬레이션
     */
    public AttackResult abnormalBehaviorPattern(String username, String password) {
        log.warn("=== Abnormal Behavior Pattern 시작 ===");
        AttackResult result = new AttackResult("Abnormal Behavior Pattern");
        
        try {
            // 정상 로그인
            simulationClient.loginJson(username, password);
            
            // 1. 비정상적 시간대 접근 (새벽 3시)
            log.warn("1단계: 비정상적 시간대 접근 (새벽 3시)");
            Map<String, String> nightHeaders = new HashMap<>();
            nightHeaders.put("X-Local-Time", "03:15:00");
            nightHeaders.put("X-Timezone", "Asia/Seoul");
            
            ResponseEntity<String> nightResponse = simulationClient.get(
                "/api/user/export-all", null, nightHeaders);
            result.addAttempt("Abnormal Time Access (3 AM)", 
                nightResponse.getStatusCode() == HttpStatus.OK, nightResponse);
            
            // 2. 대량 데이터 다운로드
            log.warn("2단계: 대량 데이터 다운로드 시도");
            AtomicInteger downloadCount = new AtomicInteger(0);
            for (int i = 0; i < 50; i++) {
                ResponseEntity<String> downloadResponse = simulationClient.get(
                    "/api/data/download?page=" + i + "&size=1000", null, null);
                if (downloadResponse.getStatusCode() == HttpStatus.OK) {
                    downloadCount.incrementAndGet();
                }
                Thread.sleep(100); // 빠른 연속 요청
            }
            result.addAttempt("Mass Data Download: " + downloadCount.get() + " files", 
                downloadCount.get() > 10, null);
            
            if (downloadCount.get() > 10) {
                log.error("!!! 대량 데이터 다운로드 성공: {} 건", downloadCount.get());
                result.setSuccessful(true);
            }
            
            // 3. 급격한 요청 증가 (DDoS 유사)
            log.warn("3단계: 급격한 요청 증가");
            List<CompletableFuture<ResponseEntity<String>>> rapidRequests = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                CompletableFuture<ResponseEntity<String>> future = CompletableFuture.supplyAsync(() ->
                    simulationClient.get("/api/user/activity", null, null)
                );
                rapidRequests.add(future);
            }
            
            int successCount = 0;
            for (CompletableFuture<ResponseEntity<String>> future : rapidRequests) {
                try {
                    ResponseEntity<String> response = future.get(5, TimeUnit.SECONDS);
                    if (response.getStatusCode() == HttpStatus.OK) successCount++;
                } catch (Exception e) {
                    // Timeout or error
                }
            }
            result.addAttempt("Rapid Request Burst: " + successCount + "/20", 
                successCount > 15, null);
            
            // 4. 비정상적 API 접근 패턴
            log.warn("4단계: 비정상적 API 접근 패턴");
            // 일반 사용자가 접근하지 않는 API 연속 호출
            List<String> suspiciousEndpoints = Arrays.asList(
                "/api/admin/debug",
                "/api/system/config",
                "/api/internal/metrics",
                "/api/debug/heap",
                "/api/actuator/env"
            );
            
            for (String endpoint : suspiciousEndpoints) {
                ResponseEntity<String> response = simulationClient.get(endpoint, null, null);
                result.addAttempt("Suspicious Endpoint: " + endpoint, 
                    response.getStatusCode() == HttpStatus.OK, response);
                Thread.sleep(attackDelayMs);
            }
            
            // 5. 계정 정보 수집 행동
            log.warn("5단계: 계정 정보 수집 행동");
            for (int userId = 1; userId <= 10; userId++) {
                simulationClient.get("/api/users/" + userId + "/public", null, null);
                Thread.sleep(200);
            }
            result.addAttempt("User Enumeration Behavior", true, null);
            
            // 6. 세션 유지 이상 행동
            log.warn("6단계: 24시간 이상 세션 유지");
            Map<String, String> longSessionHeaders = new HashMap<>();
            longSessionHeaders.put("X-Session-Duration", "86400"); // 24 hours in seconds
            longSessionHeaders.put("X-Last-Activity", "86000"); // Almost 24 hours ago
            
            ResponseEntity<String> longSessionResponse = simulationClient.get(
                "/api/user/sensitive", null, longSessionHeaders);
            result.addAttempt("Abnormally Long Session", 
                longSessionResponse.getStatusCode() == HttpStatus.OK, longSessionResponse);
            
        } catch (Exception e) {
            log.error("Abnormal Behavior Pattern 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== Abnormal Behavior Pattern 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    /**
     * Risky Network 접근 시뮬레이션
     */
    public AttackResult riskyNetworkAccess(String username, String password) {
        log.warn("=== Risky Network 접근 시작 ===");
        AttackResult result = new AttackResult("Risky Network Access");
        
        try {
            // 1. TOR 네트워크에서 접근
            log.warn("1단계: TOR 네트워크에서 접근");
            Map<String, String> torHeaders = new HashMap<>();
            torHeaders.put("X-Forwarded-For", "185.220.100.252"); // Known Tor exit node
            torHeaders.put("X-Real-IP", "185.220.100.252");
            torHeaders.put("Via", "1.1 tor-exit.node");
            
            ResponseEntity<String> torResponse = loginWithHeaders(username, password, torHeaders);
            result.addAttempt("TOR Network Access", 
                torResponse.getStatusCode() == HttpStatus.OK, torResponse);
            
            // 2. VPN을 통한 접근
            log.warn("2단계: VPN을 통한 접근");
            Map<String, String> vpnHeaders = new HashMap<>();
            vpnHeaders.put("X-Forwarded-For", "195.154.173.88"); // VPN provider IP
            vpnHeaders.put("X-VPN-Client", "NordVPN");
            vpnHeaders.put("X-Original-IP", "Hidden");
            
            ResponseEntity<String> vpnResponse = simulationClient.get(
                "/api/user/profile", null, vpnHeaders);
            result.addAttempt("VPN Access", 
                vpnResponse.getStatusCode() == HttpStatus.OK, vpnResponse);
            
            // 3. 알려진 악성 IP에서 접근
            log.warn("3단계: 알려진 악성 IP에서 접근");
            for (String riskyRange : RISKY_IP_RANGES) {
                String riskyIp = riskyRange + ThreadLocalRandom.current().nextInt(1, 255);
                Map<String, String> riskyHeaders = new HashMap<>();
                riskyHeaders.put("X-Forwarded-For", riskyIp);
                riskyHeaders.put("X-Threat-Level", "HIGH");
                
                ResponseEntity<String> riskyResponse = simulationClient.get(
                    "/api/user/data", null, riskyHeaders);
                result.addAttempt("Risky IP: " + riskyIp, 
                    riskyResponse.getStatusCode() == HttpStatus.OK, riskyResponse);
                
                if (riskyResponse.getStatusCode() == HttpStatus.OK) {
                    log.error("!!! 악성 IP에서 접근 성공: {}", riskyIp);
                    result.setSuccessful(true);
                }
                
                Thread.sleep(attackDelayMs);
            }
            
            // 4. Proxy Chain을 통한 접근
            log.warn("4단계: Proxy Chain을 통한 접근");
            Map<String, String> proxyChainHeaders = new HashMap<>();
            proxyChainHeaders.put("X-Forwarded-For", "192.168.1.1, 10.0.0.1, 172.16.0.1, 203.0.113.0");
            proxyChainHeaders.put("Via", "1.1 proxy1, 1.1 proxy2, 1.1 proxy3");
            proxyChainHeaders.put("X-Proxy-Chain", "true");
            
            ResponseEntity<String> proxyResponse = simulationClient.get(
                "/api/user/sensitive", null, proxyChainHeaders);
            result.addAttempt("Proxy Chain Access", 
                proxyResponse.getStatusCode() == HttpStatus.OK, proxyResponse);
            
            // 5. 봇넷 감염 IP에서 접근
            log.warn("5단계: 봇넷 감염 IP 시뮬레이션");
            Map<String, String> botnetHeaders = new HashMap<>();
            botnetHeaders.put("X-Forwarded-For", "45.142.120.88"); // Known botnet IP
            botnetHeaders.put("X-Threat-Intelligence", "BOTNET_C2");
            botnetHeaders.put("X-Malware-Family", "Mirai");
            
            ResponseEntity<String> botnetResponse = simulationClient.get(
                "/api/user/profile", null, botnetHeaders);
            result.addAttempt("Botnet IP Access", 
                botnetResponse.getStatusCode() == HttpStatus.OK, botnetResponse);
            
        } catch (Exception e) {
            log.error("Risky Network 접근 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== Risky Network 접근 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    /**
     * Context-based 위반 시뮬레이션
     */
    public AttackResult contextBasedViolation(String username, String password) {
        log.warn("=== Context-based 위반 시작 ===");
        AttackResult result = new AttackResult("Context-based Violation");
        
        try {
            // 정상 로그인
            simulationClient.loginJson(username, password);
            
            // 1. 업무 시간 외 민감 데이터 접근
            log.warn("1단계: 업무 시간 외 민감 데이터 접근");
            Map<String, String> afterHoursHeaders = new HashMap<>();
            afterHoursHeaders.put("X-Local-Time", "23:30:00");
            afterHoursHeaders.put("X-Day-Of-Week", "Sunday");
            
            ResponseEntity<String> afterHoursResponse = simulationClient.get(
                "/api/confidential/export", null, afterHoursHeaders);
            result.addAttempt("After Hours Sensitive Access", 
                afterHoursResponse.getStatusCode() == HttpStatus.OK, afterHoursResponse);
            
            // 2. 휴가 중 시스템 접근
            log.warn("2단계: 휴가 중 시스템 접근");
            Map<String, String> vacationHeaders = new HashMap<>();
            vacationHeaders.put("X-User-Status", "ON_VACATION");
            vacationHeaders.put("X-Vacation-Start", "2024-01-01");
            vacationHeaders.put("X-Vacation-End", "2024-01-15");
            
            ResponseEntity<String> vacationResponse = simulationClient.get(
                "/api/work/tasks", null, vacationHeaders);
            result.addAttempt("Access During Vacation", 
                vacationResponse.getStatusCode() == HttpStatus.OK, vacationResponse);
            
            // 3. 퇴사 예정자의 대량 데이터 접근
            log.warn("3단계: 퇴사 예정자의 대량 데이터 접근");
            Map<String, String> resignationHeaders = new HashMap<>();
            resignationHeaders.put("X-Employee-Status", "RESIGNATION_PENDING");
            resignationHeaders.put("X-Last-Working-Day", "2024-01-31");
            
            // 대량 데이터 다운로드 시도
            for (int i = 0; i < 10; i++) {
                ResponseEntity<String> dataResponse = simulationClient.get(
                    "/api/company/data/export?batch=" + i, null, resignationHeaders);
                result.addAttempt("Pre-resignation Data Access #" + i, 
                    dataResponse.getStatusCode() == HttpStatus.OK, dataResponse);
                Thread.sleep(500);
            }
            
            // 4. 부서 이동 후 이전 부서 데이터 접근
            log.warn("4단계: 부서 이동 후 이전 부서 데이터 접근");
            Map<String, String> deptChangeHeaders = new HashMap<>();
            deptChangeHeaders.put("X-Current-Department", "Marketing");
            deptChangeHeaders.put("X-Previous-Department", "Finance");
            deptChangeHeaders.put("X-Department-Changed", "2024-01-01");
            
            ResponseEntity<String> deptResponse = simulationClient.get(
                "/api/finance/reports", null, deptChangeHeaders);
            result.addAttempt("Previous Department Access", 
                deptResponse.getStatusCode() == HttpStatus.OK, deptResponse);
            
            // 5. 프로젝트 종료 후 접근
            log.warn("5단계: 종료된 프로젝트 데이터 접근");
            Map<String, String> projectHeaders = new HashMap<>();
            projectHeaders.put("X-Project-Status", "COMPLETED");
            projectHeaders.put("X-Project-End-Date", "2023-12-31");
            projectHeaders.put("X-User-Role-In-Project", "MEMBER");
            
            ResponseEntity<String> projectResponse = simulationClient.get(
                "/api/projects/archived/data", null, projectHeaders);
            result.addAttempt("Archived Project Access", 
                projectResponse.getStatusCode() == HttpStatus.OK, projectResponse);
            
            if (projectResponse.getStatusCode() == HttpStatus.OK) {
                log.error("!!! 종료된 프로젝트 접근 성공");
                result.setSuccessful(true);
            }
            
        } catch (Exception e) {
            log.error("Context-based 위반 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== Context-based 위반 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    // === Helper Methods ===
    
    private ResponseEntity<String> loginFromLocation(String username, String password, LocationInfo location) {
        Map<String, String> headers = createLocationHeaders(location);
        return loginWithHeaders(username, password, headers);
    }
    
    private ResponseEntity<String> loginWithHeaders(String username, String password, Map<String, String> headers) {
        // 헤더를 설정하고 로그인
        simulationClient.clearSession();
        return simulationClient.post(
            "/api/auth/login",
            Map.of("username", username, "password", password),
            headers
        );
    }
    
    private ResponseEntity<String> accessFromLocation(String endpoint, LocationInfo location) {
        Map<String, String> headers = createLocationHeaders(location);
        return simulationClient.get(endpoint, null, headers);
    }
    
    private Map<String, String> createLocationHeaders(LocationInfo location) {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Forwarded-For", location.ipAddress);
        headers.put("X-Real-IP", location.ipAddress);
        headers.put("X-Geo-Location", location.latitude + "," + location.longitude);
        headers.put("X-Timezone", location.timezone);
        headers.put("X-City", location.city);
        return headers;
    }
    
    private Map<String, String> createDeviceHeaders(DeviceInfo device) {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", device.userAgent);
        headers.put("X-Device-ID", device.deviceId);
        headers.put("X-Device-OS", device.os);
        headers.put("X-Device-Type", device.deviceType);
        return headers;
    }
    
    // === Inner Classes ===
    
    /**
     * 위치 정보
     */
    private static class LocationInfo {
        final String city;
        final String timezone;
        final double latitude;
        final double longitude;
        final String ipAddress;
        
        LocationInfo(String city, String timezone, double latitude, double longitude, String ipAddress) {
            this.city = city;
            this.timezone = timezone;
            this.latitude = latitude;
            this.longitude = longitude;
            this.ipAddress = ipAddress;
        }
    }
    
    /**
     * 디바이스 정보
     */
    private static class DeviceInfo {
        final String deviceId;
        final String os;
        final String userAgent;
        final String deviceType;
        
        DeviceInfo(String deviceId, String os, String userAgent, String deviceType) {
            this.deviceId = deviceId;
            this.os = os;
            this.userAgent = userAgent;
            this.deviceType = deviceType;
        }
    }
    
    /**
     * 공격 결과 클래스
     */
    public static class AttackResult {
        private final String attackType;
        private final List<AttemptRecord> attempts = new ArrayList<>();
        private final List<String> errors = new ArrayList<>();
        private boolean successful = false;
        private long startTime = System.currentTimeMillis();
        private long endTime;
        
        public AttackResult(String attackType) {
            this.attackType = attackType;
        }
        
        public void addAttempt(String action, boolean success, ResponseEntity<?> response) {
            attempts.add(new AttemptRecord(action, success, 
                response != null ? HttpStatus.valueOf(response.getStatusCode().value()) : HttpStatus.INTERNAL_SERVER_ERROR));
            if (success) successful = true;
        }
        
        public void addError(String error) {
            errors.add(error);
        }
        
        public void complete() {
            endTime = System.currentTimeMillis();
        }
        
        // Getters
        public String getAttackType() { return attackType; }
        public List<AttemptRecord> getAttempts() { return attempts; }
        public List<String> getErrors() { return errors; }
        public boolean isSuccessful() { return successful; }
        public void setSuccessful(boolean successful) { this.successful = successful; }
        public long getDuration() { 
            return (endTime > 0 ? endTime : System.currentTimeMillis()) - startTime; 
        }
        
        /**
         * 시도 기록
         */
        public static class AttemptRecord {
            private final String action;
            private final boolean success;
            private final HttpStatus httpStatus;
            private final long timestamp = System.currentTimeMillis();
            
            public AttemptRecord(String action, boolean success, HttpStatus httpStatus) {
                this.action = action;
                this.success = success;
                this.httpStatus = httpStatus;
            }
            
            // Getters
            public String getAction() { return action; }
            public boolean isSuccess() { return success; }
            public HttpStatus getHttpStatus() { return httpStatus; }
            public long getTimestamp() { return timestamp; }
        }
    }
}