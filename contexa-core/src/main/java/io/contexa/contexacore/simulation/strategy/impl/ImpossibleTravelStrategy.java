package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.domain.UserBehaviorPattern;
import io.contexa.contexacore.simulation.strategy.IBehaviorAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

/**
 * Impossible Travel 공격 전략 구현
 * 
 * 물리적으로 불가능한 이동을 시뮬레이션하여 계정 탈취를 시도합니다.
 * contexa의 행동 기반 탐지 시스템을 테스트합니다.
 */
public class ImpossibleTravelStrategy implements IBehaviorAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }
    private static final Logger logger = LoggerFactory.getLogger(ImpossibleTravelStrategy.class);
    
    public ImpossibleTravelStrategy() {
        // 기본 생성자
    }

    private String generateRandomIp() {
        Random random = new Random();
        return String.format("%d.%d.%d.%d",
            random.nextInt(256),
            random.nextInt(256),
            random.nextInt(256),
            random.nextInt(256));
    }
    
    // 평균 이동 속도 (km/h)
    private static final double WALKING_SPEED = 5;
    private static final double DRIVING_SPEED = 60;
    private static final double HIGH_SPEED_RAIL = 300;
    private static final double AIRPLANE_SPEED = 900;
    private static final double IMPOSSIBLE_SPEED = 1500; // 초음속
    
    // 위치 데이터베이스
    private static final List<Location> GLOBAL_LOCATIONS = initializeLocations();
    
    // 사용자별 공격 상태
    private final Map<String, UserTravelState> userStates = new ConcurrentHashMap<>();
    
    private static class UserTravelState {
        Location lastLocation;
        LocalDateTime lastAccessTime;
        List<TravelEvent> travelHistory = new ArrayList<>();
        int impossibleTravelCount = 0;
        boolean accountCompromised = false;
    }
    
    private static class TravelEvent {
        Location from;
        Location to;
        LocalDateTime fromTime;
        LocalDateTime toTime;
        double distance;
        double requiredSpeed;
        boolean impossible;
        String attackVector;
    }
    
    public AttackResult execute(String targetUser, Map<String, Object> parameters) {
        LocalDateTime startTime = LocalDateTime.now();
        
        logger.info("Executing Impossible Travel attack for user: {}", targetUser);
        
        UserTravelState state = userStates.computeIfAbsent(targetUser, k -> new UserTravelState());
        
        // 공격 시나리오 선택
        String scenario = (String) parameters.getOrDefault("scenario", "RAPID_COUNTRY_HOPPING");
        
        // 시나리오별 실행
        AttackResult result = switch (scenario) {
            case "RAPID_COUNTRY_HOPPING" -> executeRapidCountryHopping(state, targetUser);
            case "SIMULTANEOUS_LOGINS" -> executeSimultaneousLogins(state, targetUser);
            case "VPN_JUMPING" -> executeVpnJumping(state, targetUser);
            case "TIME_ZONE_MANIPULATION" -> executeTimeZoneManipulation(state, targetUser);
            case "CREDENTIAL_SHARING" -> executeCredentialSharing(state, targetUser);
            default -> executeRapidCountryHopping(state, targetUser);
        };
        
        // 상태 업데이트
        updateTravelState(state, result);
        
        return result;
    }
    
    private AttackResult executeRapidCountryHopping(UserTravelState state, String targetUser) {
        LocalDateTime now = LocalDateTime.now();

        // 두 개의 원거리 위치 선택
        Location location1 = GLOBAL_LOCATIONS.get(ThreadLocalRandom.current().nextInt(GLOBAL_LOCATIONS.size()));
        Location location2 = selectDistantLocation(location1);

        // 짧은 시간 간격 설정 (5-30분)
        int minutesBetween = ThreadLocalRandom.current().nextInt(5, 31);

        // 거리 계산
        double distance = calculateDistance(location1, location2);
        double requiredSpeed = (distance / minutesBetween) * 60; // km/h

        // 공격 소스 IP 생성
        String sourceIp = generateIP(location1);

        // 공격 결과 생성
        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .attackType(AttackResult.AttackType.IMPOSSIBLE_TRAVEL)
            .attackName("Impossible Travel - Rapid Country Hopping")
            .executionTime(now)
            .timestamp(now)
            .targetUser(targetUser)
            .description(String.format("Travel from %s to %s in %d minutes (%.0f km/h required)",
                location1.getCity(), location2.getCity(), minutesBetween, requiredSpeed))
            .mitreTechnique("T1078.004")
            .sourceIp(sourceIp)
            .attackDetails(Map.of(
                "from_location", location1.getCity() + ", " + location1.getCountry(),
                "to_location", location2.getCity() + ", " + location2.getCountry(),
                "distance_km", distance,
                "time_minutes", minutesBetween,
                "required_speed_kmh", requiredSpeed
            ))
            .build();

        // 물리적 불가능 여부 판단
        boolean impossible = requiredSpeed > AIRPLANE_SPEED;
        result.setAttackSuccessful(impossible);
        result.setSuccessful(impossible);

        // 이벤트 발행 - Authentication Success Event 사용 (로그인 성공으로 시뮬레이션)
        if (eventPublisher != null) {
            if (impossible) {
                // 불가능한 여행으로 의심스러운 로그인 성공
                eventPublisher.publishAuthenticationSuccess(
                    result,
                    targetUser,
                    sourceIp,
                    UUID.randomUUID().toString(), // sessionId
                    true, // anomalyDetected
                    0.1 // trustScore (매우 낮음)
                );
            } else {
                // 의심스럽지만 가능한 여행
                eventPublisher.publishAuthenticationSuccess(
                    result,
                    targetUser,
                    sourceIp,
                    UUID.randomUUID().toString(), // sessionId
                    true, // anomalyDetected
                    0.4 // trustScore (낮음)
                );
            }
        }

        // 탐지 시뮬레이션
        simulateDetection(result, requiredSpeed);

        // 위험도 평가
        evaluateRisk(result, requiredSpeed);

        // 증거 수집
        collectEvidence(result, location1, location2, minutesBetween, distance, requiredSpeed);

        return result;
    }
    
    private AttackResult executeSimultaneousLogins(UserTravelState state, String targetUser) {
        LocalDateTime now = LocalDateTime.now();

        // 3-5개의 서로 다른 위치에서 동시 로그인
        int locationCount = ThreadLocalRandom.current().nextInt(3, 6);
        List<Location> locations = selectMultipleLocations(locationCount);

        // 첫 번째 위치의 IP 사용
        String sourceIp = generateIP(locations.get(0));

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .attackType(AttackResult.AttackType.IMPOSSIBLE_TRAVEL)
            .attackName("Impossible Travel - Simultaneous Logins")
            .executionTime(now)
            .timestamp(now)
            .targetUser(targetUser)
            .description(String.format("Simultaneous logins from %d different locations", locationCount))
            .mitreTechnique("T1078.004")
            .sourceIp(sourceIp)
            .attackDetails(Map.of(
                "location_count", locationCount,
                "locations", locations.stream()
                    .map(loc -> loc.getCity() + ", " + loc.getCountry())
                    .collect(Collectors.toList()),
                "attack_type", "simultaneous_login"
            ))
            .attackSuccessful(true)
            .successful(true)
            .build();

        // 이벤트 발행 - Authentication Success Event 사용 (의심스러운 동시 로그인)
        if (eventPublisher != null) {
            eventPublisher.publishAuthenticationSuccess(
                result,
                targetUser,
                sourceIp,
                UUID.randomUUID().toString(), // sessionId
                true, // anomalyDetected
                0.05 // trustScore (매우 낮음)
            );
        }

        // 동시 로그인은 항상 불가능
        result.setDetected(ThreadLocalRandom.current().nextDouble() < 0.9); // 90% 탐지율

        if (result.isDetected()) {
            result.setDetectionTime(now.plusSeconds(ThreadLocalRandom.current().nextInt(1, 10)));
            result.setDetectionTimeMs(ThreadLocalRandom.current().nextLong(100, 1000));
            result.setDetectionMethod("behavioral_analysis");
            result.setBlocked(true);
        }

        result.setRiskScore(0.95);
        result.setRiskLevel(AttackResult.RiskLevel.CRITICAL.name());
        result.setImpactAssessment("Critical - Clear indication of account compromise");

        return result;
    }
    
    private AttackResult executeVpnJumping(UserTravelState state, String targetUser) {
        LocalDateTime now = LocalDateTime.now();
        
        // VPN 서버 위치들
        List<Location> vpnLocations = Arrays.asList(
            new Location("Netherlands", "Amsterdam", 52.3676, 4.9041),
            new Location("Switzerland", "Zurich", 47.3769, 8.5417),
            new Location("Singapore", "Singapore", 1.3521, 103.8198),
            new Location("United States", "New York", 40.7128, -74.0060)
        );
        
        // 빠른 VPN 전환 시뮬레이션
        int jumps = ThreadLocalRandom.current().nextInt(5, 10);
        
        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .attackType(AttackResult.AttackType.IMPOSSIBLE_TRAVEL)
            .attackName("Impossible Travel - VPN Jumping")
            .executionTime(now)
            .timestamp(now)
            .targetUser(targetUser)
            .description(String.format("Rapid VPN server changes across %d locations", jumps))
            .mitreTechnique("T1090.003")
            .build();
        
        // VPN 점프는 의심스럽지만 기술적으로 가능
        boolean suspicious = jumps > 7;
        result.setAttackSuccessful(suspicious);
        result.setSuccessful(suspicious);
        
        // 탐지 확률은 점프 횟수에 비례
        double detectionProb = Math.min(0.1 * jumps, 0.9);
        result.setDetected(ThreadLocalRandom.current().nextDouble() < detectionProb);
        
        if (result.isDetected()) {
            result.setDetectionTime(now.plusSeconds(ThreadLocalRandom.current().nextInt(5, 30)));
            result.setDetectionTimeMs(ThreadLocalRandom.current().nextLong(5000, 30000));
            result.setDetectionMethod("vpn_detection");
            result.setBlocked(ThreadLocalRandom.current().nextDouble() < 0.5);
        }
        
        result.setRiskScore(0.6 + (jumps * 0.05));
        result.setRiskLevel(AttackResult.RiskLevel.fromScore(result.getRiskScore()).name());
        
        return result;
    }
    
    private AttackResult executeTimeZoneManipulation(UserTravelState state, String targetUser) {
        LocalDateTime now = LocalDateTime.now();
        
        // 시간대 조작 공격
        String[] timezones = {"America/Los_Angeles", "Europe/London", "Asia/Tokyo", "Australia/Sydney"};
        String fromTz = timezones[ThreadLocalRandom.current().nextInt(timezones.length)];
        String toTz = timezones[ThreadLocalRandom.current().nextInt(timezones.length)];
        
        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .attackType(AttackResult.AttackType.IMPOSSIBLE_TRAVEL)
            .attackName("Impossible Travel - Timezone Manipulation")
            .executionTime(now)
            .timestamp(now)
            .targetUser(targetUser)
            .description(String.format("Timezone manipulation from %s to %s", fromTz, toTz))
            .mitreTechnique("T1070.006")
            .build();
        
        result.setAttackSuccessful(ThreadLocalRandom.current().nextDouble() < 0.4);
        result.setSuccessful(result.isAttackSuccessful());
        
        // 시간대 조작은 탐지가 어려움
        result.setDetected(ThreadLocalRandom.current().nextDouble() < 0.3);
        
        if (result.isDetected()) {
            result.setDetectionTime(now.plusMinutes(ThreadLocalRandom.current().nextInt(5, 60)));
            result.setDetectionTimeMs(ThreadLocalRandom.current().nextLong(300000, 3600000));
            result.setDetectionMethod("timestamp_analysis");
            result.setBlocked(false); // 보통 차단하지 않고 모니터링
        }
        
        result.setRiskScore(0.5);
        result.setRiskLevel(AttackResult.RiskLevel.MEDIUM.name());
        
        return result;
    }
    
    private AttackResult executeCredentialSharing(UserTravelState state, String targetUser) {
        LocalDateTime now = LocalDateTime.now();
        
        // 여러 위치에서 동일 자격증명 사용
        int userCount = ThreadLocalRandom.current().nextInt(2, 5);
        List<Location> locations = selectMultipleLocations(userCount);
        
        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .attackType(AttackResult.AttackType.IMPOSSIBLE_TRAVEL)
            .attackName("Impossible Travel - Credential Sharing")
            .executionTime(now)
            .timestamp(now)
            .targetUser(targetUser)
            .description(String.format("Credential sharing detected across %d locations", userCount))
            .mitreTechnique("T1078.003")
            .build();
        
        result.setAttackSuccessful(true);
        result.setSuccessful(true);
        
        // 자격증명 공유는 높은 확률로 탐지
        result.setDetected(ThreadLocalRandom.current().nextDouble() < 0.85);
        
        if (result.isDetected()) {
            result.setDetectionTime(now.plusMinutes(ThreadLocalRandom.current().nextInt(1, 15)));
            result.setDetectionTimeMs(ThreadLocalRandom.current().nextLong(60000, 900000));
            result.setDetectionMethod("credential_sharing_detection");
            result.setBlocked(ThreadLocalRandom.current().nextDouble() < 0.7);
            result.setRequiresMfa(true);
        }
        
        result.setRiskScore(0.8);
        result.setRiskLevel(AttackResult.RiskLevel.HIGH.name());
        result.setImpactAssessment("High - Potential credential compromise or policy violation");
        
        return result;
    }
    
    private void simulateDetection(AttackResult result, double requiredSpeed) {
        Random random = ThreadLocalRandom.current();
        
        // 속도에 따른 탐지 확률
        double detectionProbability;
        if (requiredSpeed > IMPOSSIBLE_SPEED) {
            detectionProbability = 0.99; // 거의 확실히 탐지
        } else if (requiredSpeed > AIRPLANE_SPEED) {
            detectionProbability = 0.9;
        } else if (requiredSpeed > HIGH_SPEED_RAIL) {
            detectionProbability = 0.7;
        } else if (requiredSpeed > DRIVING_SPEED) {
            detectionProbability = 0.5;
        } else {
            detectionProbability = 0.2;
        }
        
        boolean detected = random.nextDouble() < detectionProbability;
        result.setDetected(detected);
        
        if (detected) {
            result.setDetectionTime(LocalDateTime.now());
            result.setDetectionTimeMs((long)(random.nextDouble() * 3000 + 500)); // 0.5-3.5초
            
            // 탐지 방법
            if (requiredSpeed > AIRPLANE_SPEED) {
                result.setDetectionMethod("impossible_travel");
                result.getTriggeredPolicies().add("IMPOSSIBLE_TRAVEL_POLICY");
            } else {
                result.setDetectionMethod("behavioral_anomaly");
                result.getTriggeredPolicies().add("BEHAVIORAL_ANOMALY_POLICY");
            }
            
            // AI 신뢰도
            result.setAiConfidenceScore(Math.min(0.5 + (requiredSpeed / 3000), 0.99));
            result.setAiThreatCategory("Account Takeover");
            result.setAiRecommendation("Require MFA and verify user identity");
            
            // 차단 여부
            result.setBlocked(requiredSpeed > AIRPLANE_SPEED);
            result.setRequiresMfa(true);
        }
    }
    
    private void evaluateRisk(AttackResult result, double requiredSpeed) {
        double riskScore;
        
        if (requiredSpeed > IMPOSSIBLE_SPEED) {
            riskScore = 0.99;
        } else if (requiredSpeed > AIRPLANE_SPEED) {
            riskScore = 0.9;
        } else if (requiredSpeed > HIGH_SPEED_RAIL) {
            riskScore = 0.75;
        } else if (requiredSpeed > DRIVING_SPEED) {
            riskScore = 0.6;
        } else {
            riskScore = 0.3;
        }
        
        result.setRiskScore(riskScore);
        result.setRiskLevel(AttackResult.RiskLevel.fromScore(riskScore).name());
        
        // 영향도 평가
        if (riskScore >= 0.9) {
            result.setImpactAssessment("Critical - Clear indication of account compromise");
        } else if (riskScore >= 0.75) {
            result.setImpactAssessment("High - Likely account compromise or credential sharing");
        } else if (riskScore >= 0.5) {
            result.setImpactAssessment("Medium - Suspicious travel pattern detected");
        } else {
            result.setImpactAssessment("Low - Unusual but potentially legitimate travel");
        }
    }
    
    private void collectEvidence(AttackResult result, Location from, Location to, 
                                int minutes, double distance, double speed) {
        // 증거 수집
        Map<String, Object> evidenceData = new HashMap<>();
        evidenceData.put("from_location", String.format("%s, %s", from.getCity(), from.getCountry()));
        evidenceData.put("to_location", String.format("%s, %s", to.getCity(), to.getCountry()));
        evidenceData.put("from_ip", generateIP(from));
        evidenceData.put("to_ip", generateIP(to));
        evidenceData.put("time_difference_minutes", minutes);
        evidenceData.put("distance_km", String.format("%.2f", distance));
        evidenceData.put("required_speed_kmh", String.format("%.2f", speed));
        evidenceData.put("physical_possibility", speed <= AIRPLANE_SPEED ? "POSSIBLE" : "IMPOSSIBLE");
        
        AttackResult.Evidence evidence = AttackResult.Evidence.builder()
            .type("travel_analysis")
            .timestamp(LocalDateTime.now())
            .source("GeoIP Database")
            .content(String.format("Impossible travel detected: %.0f km in %d minutes", distance, minutes))
            .metadata(evidenceData)
            .build();
        
        result.getEvidences().add(evidence);
        
        // HTTP 헤더에 위치 정보 추가
        result.getHttpHeaders().put("X-Forwarded-For", generateIP(to));
        result.getHttpHeaders().put("X-Real-IP", generateIP(from));
        result.getHttpHeaders().put("CF-IPCountry", to.getCountry());
    }
    
    private void updateTravelState(UserTravelState state, AttackResult result) {
        // 상태 업데이트 로직
        if (result.isAttackSuccessful()) {
            state.impossibleTravelCount++;
            if (state.impossibleTravelCount > 3) {
                state.accountCompromised = true;
            }
        }
        state.lastAccessTime = LocalDateTime.now();
    }
    
    private double calculateDistance(Location loc1, Location loc2) {
        // Haversine formula for calculating distance between two points on Earth
        double R = 6371; // Earth's radius in kilometers
        double lat1Rad = Math.toRadians(loc1.getLatitude());
        double lat2Rad = Math.toRadians(loc2.getLatitude());
        double deltaLat = Math.toRadians(loc2.getLatitude() - loc1.getLatitude());
        double deltaLon = Math.toRadians(loc2.getLongitude() - loc1.getLongitude());
        
        double a = Math.sin(deltaLat/2) * Math.sin(deltaLat/2) +
                  Math.cos(lat1Rad) * Math.cos(lat2Rad) *
                  Math.sin(deltaLon/2) * Math.sin(deltaLon/2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        
        return R * c;
    }
    
    private Location selectDistantLocation(Location from) {
        // 최소 5000km 이상 떨어진 위치 선택
        Location selected;
        do {
            selected = GLOBAL_LOCATIONS.get(ThreadLocalRandom.current().nextInt(GLOBAL_LOCATIONS.size()));
        } while (calculateDistance(from, selected) < 5000);
        return selected;
    }
    
    private List<Location> selectMultipleLocations(int count) {
        List<Location> selected = new ArrayList<>();
        Set<String> usedCountries = new HashSet<>();
        
        while (selected.size() < count && selected.size() < GLOBAL_LOCATIONS.size()) {
            Location loc = GLOBAL_LOCATIONS.get(ThreadLocalRandom.current().nextInt(GLOBAL_LOCATIONS.size()));
            if (!usedCountries.contains(loc.getCountry())) {
                selected.add(loc);
                usedCountries.add(loc.getCountry());
            }
        }
        
        return selected;
    }
    
    private String generateIP(Location location) {
        // 위치 기반 IP 생성 (시뮬레이션용)
        Random random = ThreadLocalRandom.current();
        switch (location.getCountry()) {
            case "United States":
                return String.format("8.%d.%d.%d", random.nextInt(256), random.nextInt(256), random.nextInt(256));
            case "China":
                return String.format("1.%d.%d.%d", random.nextInt(256), random.nextInt(256), random.nextInt(256));
            case "Japan":
                return String.format("133.%d.%d.%d", random.nextInt(256), random.nextInt(256), random.nextInt(256));
            case "Germany":
                return String.format("91.%d.%d.%d", random.nextInt(256), random.nextInt(256), random.nextInt(256));
            case "United Kingdom":
                return String.format("81.%d.%d.%d", random.nextInt(256), random.nextInt(256), random.nextInt(256));
            default:
                return String.format("%d.%d.%d.%d", 
                    random.nextInt(1, 255), random.nextInt(256), random.nextInt(256), random.nextInt(256));
        }
    }
    
    private static List<Location> initializeLocations() {
        List<Location> locations = new ArrayList<>();
        
        // Major cities around the world
        locations.add(new Location("United States", "New York", 40.7128, -74.0060));
        locations.add(new Location("United States", "Los Angeles", 34.0522, -118.2437));
        locations.add(new Location("United Kingdom", "London", 51.5074, -0.1278));
        locations.add(new Location("France", "Paris", 48.8566, 2.3522));
        locations.add(new Location("Germany", "Berlin", 52.5200, 13.4050));
        locations.add(new Location("Russia", "Moscow", 55.7558, 37.6173));
        locations.add(new Location("China", "Beijing", 39.9042, 116.4074));
        locations.add(new Location("Japan", "Tokyo", 35.6762, 139.6503));
        locations.add(new Location("South Korea", "Seoul", 37.5665, 126.9780));
        locations.add(new Location("India", "Mumbai", 19.0760, 72.8777));
        locations.add(new Location("Australia", "Sydney", -33.8688, 151.2093));
        locations.add(new Location("Brazil", "São Paulo", -23.5505, -46.6333));
        locations.add(new Location("South Africa", "Johannesburg", -26.2041, 28.0473));
        locations.add(new Location("Egypt", "Cairo", 30.0444, 31.2357));
        locations.add(new Location("Singapore", "Singapore", 1.3521, 103.8198));
        
        return locations;
    }
    
    // IBehaviorAttack interface implementations
    @Override
    public BehaviorResult mimicBehavior(UserBehaviorPattern pattern) {
        BehaviorResult result = new BehaviorResult();
        result.setAnomalyDetected(false);
        result.setAnomalyType("MIMIC_ATTEMPT");
        result.setAnomalyScore(ThreadLocalRandom.current().nextDouble(0.2, 0.5));
        return result;
    }
    
    @Override
    public BehaviorResult performImpossibleTravel(String userId, List<Location> locations, List<Integer> timeIntervals) {
        BehaviorResult result = new BehaviorResult();
        
        if (locations.size() < 2) {
            result.setAnomalyDetected(false);
            return result;
        }
        
        double maxRequiredSpeed = 0;
        for (int i = 0; i < locations.size() - 1 && i < timeIntervals.size(); i++) {
            double distance = calculateDistance(locations.get(i), locations.get(i + 1));
            double speed = (distance / timeIntervals.get(i)) * 3600; // km/h
            maxRequiredSpeed = Math.max(maxRequiredSpeed, speed);
        }
        
        result.setAnomalyDetected(maxRequiredSpeed > AIRPLANE_SPEED);
        result.setAnomalyType("IMPOSSIBLE_TRAVEL");
        result.setAnomalyScore(Math.min(maxRequiredSpeed / IMPOSSIBLE_SPEED, 1.0));
        result.setZeroTrustViolation(maxRequiredSpeed > HIGH_SPEED_RAIL);
        
        return result;
    }
    
    @Override
    public BehaviorResult performAbnormalTimeAccess(String userId, LocalDateTime accessTime) {
        BehaviorResult result = new BehaviorResult();
        int hour = accessTime.getHour();
        
        // 새벽 2-5시를 비정상 시간으로 간주
        boolean abnormal = hour >= 2 && hour <= 5;
        
        result.setAnomalyDetected(abnormal);
        result.setAnomalyType("ABNORMAL_TIME_ACCESS");
        result.setAnomalyScore(abnormal ? 0.7 : 0.2);
        
        return result;
    }
    
    @Override
    public BehaviorResult violateDeviceTrust(String userId, String deviceFingerprint) {
        BehaviorResult result = new BehaviorResult();
        
        // 랜덤하게 장치 신뢰도 위반 시뮬레이션
        boolean violated = ThreadLocalRandom.current().nextDouble() < 0.3;
        
        result.setAnomalyDetected(violated);
        result.setAnomalyType("DEVICE_TRUST_VIOLATION");
        result.setAnomalyScore(violated ? 0.8 : 0.1);
        result.setZeroTrustViolation(violated);
        
        return result;
    }
    
    @Override
    public BehaviorResult performMassDataAccess(String userId, long dataVolume, int duration) {
        BehaviorResult result = new BehaviorResult();
        
        // 데이터 접근 속도 계산 (MB/s)
        double dataRateMBps = (dataVolume / (1024.0 * 1024.0)) / duration;
        
        // 10 MB/s 이상을 비정상으로 간주
        boolean abnormal = dataRateMBps > 10;
        
        result.setAnomalyDetected(abnormal);
        result.setAnomalyType("MASS_DATA_ACCESS");
        result.setAnomalyScore(Math.min(dataRateMBps / 50, 1.0));
        
        return result;
    }
    
    @Override
    public BehaviorResult generateAnomalousNetworkPattern(String userId, NetworkPattern networkPattern) {
        BehaviorResult result = new BehaviorResult();
        
        boolean anomalous = networkPattern.isTorUsage() || 
                          networkPattern.isVpnUsage() || 
                          networkPattern.getUnusualPorts().size() > 3;
        
        result.setAnomalyDetected(anomalous);
        result.setAnomalyType("NETWORK_ANOMALY");
        result.setAnomalyScore(anomalous ? 0.75 : 0.25);
        
        return result;
    }
    
    @Override
    public BehaviorResult simulateAccountTakeover(UserBehaviorPattern legitimatePattern, 
                                                 UserBehaviorPattern attackerPattern) {
        BehaviorResult result = new BehaviorResult();
        
        result.setAnomalyDetected(true);
        result.setAnomalyType("ACCOUNT_TAKEOVER");
        result.setAnomalyScore(0.9);
        result.setZeroTrustViolation(true);
        result.setRiskAssessment("Critical - Account takeover detected");
        
        return result;
    }
    
    @Override
    public BehaviorResult generateInsiderThreat(String userId, List<ThreatIndicator> threatIndicators) {
        BehaviorResult result = new BehaviorResult();
        
        double threatScore = threatIndicators.size() * 0.2;
        
        result.setAnomalyDetected(threatScore > 0.5);
        result.setAnomalyType("INSIDER_THREAT");
        result.setAnomalyScore(Math.min(threatScore, 1.0));
        
        List<String> violations = threatIndicators.stream()
            .map(ThreatIndicator::getDescription)
            .collect(Collectors.toList());
        result.setViolatedPolicies(violations);
        
        return result;
    }
    
    public List<AttackResult> generateCampaign(String targetOrganization, int numberOfAttacks) {
        List<AttackResult> results = new ArrayList<>();
        
        String[] scenarios = {
            "RAPID_COUNTRY_HOPPING",
            "SIMULTANEOUS_LOGINS",
            "VPN_JUMPING",
            "TIME_ZONE_MANIPULATION",
            "CREDENTIAL_SHARING"
        };
        
        for (int i = 0; i < numberOfAttacks; i++) {
            String scenario = scenarios[i % scenarios.length];
            Map<String, Object> params = new HashMap<>();
            params.put("scenario", scenario);
            params.put("campaignId", UUID.randomUUID().toString());
            
            String targetUser = String.format("user_%d@%s", i, targetOrganization);
            AttackResult result = execute(targetUser, params);
            result.setCampaignId((String) params.get("campaignId"));
            
            results.add(result);
            
            // 공격 간 지연
            try {
                Thread.sleep(ThreadLocalRandom.current().nextInt(500, 2000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return results;
    }
    
    public Map<String, Object> getStrategyMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        metrics.put("strategyName", "IMPOSSIBLE_TRAVEL");
        metrics.put("successRate", 0.65);
        metrics.put("detectionRate", 0.85);
        metrics.put("averageRiskScore", 0.78);
        metrics.put("scenarioCount", 5);
        
        Map<String, Double> scenarioSuccessRates = new HashMap<>();
        scenarioSuccessRates.put("RAPID_COUNTRY_HOPPING", 0.75);
        scenarioSuccessRates.put("SIMULTANEOUS_LOGINS", 0.90);
        scenarioSuccessRates.put("VPN_JUMPING", 0.60);
        scenarioSuccessRates.put("TIME_ZONE_MANIPULATION", 0.40);
        scenarioSuccessRates.put("CREDENTIAL_SHARING", 0.85);
        metrics.put("scenarioSuccessRates", scenarioSuccessRates);
        
        return metrics;
    }
    
    @Override
    public String getSuccessCriteria() {
        return "Successfully detect physically impossible travel patterns indicating account compromise";
    }
    
    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.NONE; // 불가능한 이동은 권한 불필요
    }
    
    @Override
    public AttackResult execute(AttackContext context) {
        return execute(context.getTargetUser(), context.getParameters());
    }
    
    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.IMPOSSIBLE_TRAVEL;
    }
    
    @Override
    public int getPriority() {
        return 90; // 높은 우선순위
    }
    
    @Override
    public AttackCategory getCategory() {
        return AttackCategory.BEHAVIORAL;
    }
    
    @Override
    public boolean validateContext(AttackContext context) {
        return context != null && context.getTargetUser() != null;
    }
    
    @Override
    public long getEstimatedDuration() {
        return 10000; // 10초
    }
    
    @Override
    public String getDescription() {
        return "Impossible travel detection simulating physically impossible login locations indicating account compromise";
    }
}