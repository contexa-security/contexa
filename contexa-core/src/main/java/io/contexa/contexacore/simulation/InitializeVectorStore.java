package io.contexa.contexacore.simulation;

import io.contexa.contexacore.hcad.constants.HCADRedisKeys;
import io.contexa.contexacore.hcad.domain.BaselineVector;
import io.contexa.contexacore.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.service.HCADBaselineLearningService;
import io.contexa.contexacore.simulation.config.SimulationConfig;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Vector Store 초기화를 위한 테스트 데이터 생성기
 *
 * 정상 사용자 행동 패턴을 Vector Store에 저장하여
 * Zero Trust AI가 학습할 수 있도록 베이스라인을 구축합니다.
 *
 * 실행 방법:
 * 1. contexa 서버 실행 (PostgreSQL, Redis, Kafka 필요)
 * 2. 이 클래스를 Spring Boot Application으로 실행
 * 3. 콘솔에서 데이터 생성 완료 메시지 확인
 */
//@Component
@RequiredArgsConstructor
public class InitializeVectorStore implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(InitializeVectorStore.class);
    private final BehaviorVectorService behaviorVectorService;
    private final SimulationConfig simulationConfig;
    private final HCADBaselineLearningService baselineLearningService;
    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${hcad.baseline.redis.ttl-days:30}")
    private int baselineTtlDays;

    /**
     * @Protectable 리소스 접근 패턴 정의
     */
    static class ProtectableAccessPattern {
        String methodName;          // @Protectable 메소드명
        int dailyFrequency;         // 일일 평균 접근 빈도
        String accessTimeRange;     // 정상 접근 시간대 (예: "09:00-18:00")
        String accessPurpose;       // 접근 목적
        int maxBulkSize;           // 최대 벌크 조회 크기

        ProtectableAccessPattern(String methodName, int dailyFrequency, String accessTimeRange,
                                String accessPurpose, int maxBulkSize) {
            this.methodName = methodName;
            this.dailyFrequency = dailyFrequency;
            this.accessTimeRange = accessTimeRange;
            this.accessPurpose = accessPurpose;
            this.maxBulkSize = maxBulkSize;
        }
    }

    private static final List<String> USERS = Arrays.asList(
        "admin", "dev_lead", "dev_user", "op_user", "finance_manager"
    );

    /**
     * 사용자별 @Protectable 리소스 접근 패턴 정의
     * 각 사용자의 역할에 따른 정상적인 민감 리소스 접근 패턴을 정의
     */
    private static final Map<String, List<ProtectableAccessPattern>> USER_PROTECTABLE_PATTERNS = new HashMap<>();
    static {
        // Admin: 시스템 관리자 - 모든 리소스 접근 가능하지만 신중하게 사용
        USER_PROTECTABLE_PATTERNS.put("admin", Arrays.asList(
            new ProtectableAccessPattern("getCustomerData", 5, "09:00-18:00", "개별고객확인", 1),
            new ProtectableAccessPattern("getAllCustomerData", 1, "10:00-11:00", "일일보고서생성", 100),
            new ProtectableAccessPattern("updateCustomerData", 2, "14:00-16:00", "정보수정요청처리", 1),
            new ProtectableAccessPattern("deleteCustomerData", 0, "", "긴급삭제요청", 1)  // 거의 사용하지 않음
        ));

        // Dev Lead: 개발팀장 - 테스트 목적 제한적 접근
        USER_PROTECTABLE_PATTERNS.put("dev_lead", Arrays.asList(
            new ProtectableAccessPattern("getCustomerData", 3, "10:00-17:00", "기능테스트", 1),
            new ProtectableAccessPattern("getAllCustomerData", 0, "", "권한없음", 0),  // 접근 불가
            new ProtectableAccessPattern("updateCustomerData", 1, "14:00-15:00", "테스트데이터수정", 1),
            new ProtectableAccessPattern("deleteCustomerData", 0, "", "권한없음", 0)   // 접근 불가
        ));

        // Dev User: 일반 개발자 - 매우 제한적 접근
        USER_PROTECTABLE_PATTERNS.put("dev_user", Arrays.asList(
            new ProtectableAccessPattern("getCustomerData", 1, "10:00-17:00", "디버깅", 1),
            new ProtectableAccessPattern("getAllCustomerData", 0, "", "권한없음", 0),
            new ProtectableAccessPattern("updateCustomerData", 0, "", "권한없음", 0),
            new ProtectableAccessPattern("deleteCustomerData", 0, "", "권한없음", 0)
        ));

        // Op User: 운영팀 - 읽기 위주 접근
        USER_PROTECTABLE_PATTERNS.put("op_user", Arrays.asList(
            new ProtectableAccessPattern("getCustomerData", 8, "09:00-18:00", "고객문의대응", 1),
            new ProtectableAccessPattern("getAllCustomerData", 0, "", "권한없음", 0),
            new ProtectableAccessPattern("updateCustomerData", 1, "14:00-16:00", "연락처수정", 1),
            new ProtectableAccessPattern("deleteCustomerData", 0, "", "권한없음", 0)
        ));

        // Finance Manager: 재무관리자 - 보고서용 대량 조회
        USER_PROTECTABLE_PATTERNS.put("finance_manager", Arrays.asList(
            new ProtectableAccessPattern("getCustomerData", 10, "09:00-18:00", "거래내역확인", 1),
            new ProtectableAccessPattern("getAllCustomerData", 2, "09:00-10:00", "일일정산", 500),
            new ProtectableAccessPattern("updateCustomerData", 0, "", "권한없음", 0),
            new ProtectableAccessPattern("deleteCustomerData", 0, "", "권한없음", 0)
        ));
    }

    private static final List<String> NORMAL_ACTIVITIES = Arrays.asList(
        "로그인",
        "대시보드 조회",
        "프로필 수정",
        "보고서 조회",
        "시스템 설정 확인",
        "로그 조회",
        "사용자 목록 조회",
        "권한 확인",
        "알림 확인",
        "로그아웃",
        "ProtectableDataService.getCustomerData 단일 조회",
        "개인정보 조회 - 단건",
        "고객정보 검색"
    );

    private static final List<String> ADMIN_ACTIVITIES = Arrays.asList(
        "사용자 생성",
        "권한 부여",
        "시스템 설정 변경",
        "감사 로그 조회",
        "보안 정책 수정"
    );

    private static final List<String> DEV_ACTIVITIES = Arrays.asList(
        "소스 코드 조회",
        "API 테스트",
        "디버그 로그 확인",
        "배포 상태 확인",
        "성능 메트릭 조회"
    );

    private static final List<String> FINANCE_ACTIVITIES = Arrays.asList(
        "재무 보고서 조회",
        "거래 내역 확인",
        "예산 현황 조회",
        "결재 문서 확인",
        "비용 분석 보고서 다운로드"
    );

    /**
     * 컨텍스트 기반 위험도 계산
     * ContextManipulationController의 로직과 동일하게 구현
     */
    private double calculateContextRiskScore(BehavioralAnalysisContext context) {
        double score = 0.0;
        SimulationConfig.RiskScores riskScores = simulationConfig.getRiskScores();

        // IP 기반 위험도 - 설정에서 의심스러운 IP 확인
        boolean isSuspiciousIp = simulationConfig.getAttackIps().getSuspicious()
                .contains(context.getRemoteIp());
        if (isSuspiciousIp) {
            score += riskScores.getIpChange() * 100;
        } else if (context.getRemoteIp() != null && !context.getRemoteIp().startsWith("192.168")) {
            score += (riskScores.getIpChange() * 100) / 2; // 외부 IP
        }

        // 시간 기반 위험도 - 설정에서 정상/비정상 시간 확인
        LocalDateTime lastActivityTime = context.getLastActivityTime();
        if (lastActivityTime != null) {
            int hour = lastActivityTime.getHour();
            SimulationConfig.Timezones.NormalHours normalHours = simulationConfig.getTimezones().getNormalHours();
            SimulationConfig.Timezones.SuspiciousHours suspiciousHours = simulationConfig.getTimezones().getSuspiciousHours();

            if (hour < normalHours.getStart() || hour >= normalHours.getEnd()) {
                // 비정상 시간대
                if (suspiciousHours.getEarlyMorning().contains(hour) ||
                        suspiciousHours.getLateNight().contains(hour)) {
                    score += riskScores.getOffHours() * 100;
                }
            }
        }

        // User-Agent 기반 위험도 - 설정에서 의심스러운 UA 확인
        boolean isSuspiciousAgent = simulationConfig.getUserAgents().getSuspicious().stream()
                .anyMatch(ua -> context.getUserAgent() != null &&
                        context.getUserAgent().toLowerCase().contains(ua.toLowerCase()));
        if (isSuspiciousAgent) {
            score += riskScores.getSuspiciousAgent() * 100;
        }

        // 새 디바이스/위치 위험도
        if (context.isNewDevice()) {
            score += riskScores.getDeviceChange() * 100;
        }
        if (context.isNewLocation()) {
            score += riskScores.getLocationChange() * 100;
        }

        // 활동 속도 기반 위험도
        if (context.getActivityVelocity() > 60.0) { // 분당 60개 이상
            score += riskScores.getRepeatedAttempts() * 100;
        }

        return Math.min(score, 100.0); // 최대 100
    }

    @Override
    public void run(String... args) throws Exception {
        log.info("========================================");
        log.info("Vector Store 초기화 시작 (개선 버전)");
        log.info("========================================");

        Random random = new Random();
        int totalPatterns = 0;

        // 1. 정상 패턴 생성 (30일간)
        log.info("\n[1단계] 정상 행동 패턴 생성 (30일)");
        totalPatterns += generateNormalPatterns(30, random);

        // 2. @Protectable 리소스 정상 접근 패턴 생성 (30일간)
        log.info("\n[2단계] @Protectable 리소스 정상 접근 패턴 생성 (30일)");
        totalPatterns += generateProtectableNormalPatterns(30, random);

        // 3. 경계선 패턴 생성 (월말, 긴급상황 등)
        log.info("\n[3단계] 경계선 패턴 생성 (정상이지만 주의 필요)");
        totalPatterns += generateBorderlinePatterns(random);

        // 4. 공격자 시나리오 패턴 생성
        log.info("\n[4단계] 공격자 시나리오 패턴 생성");
        totalPatterns += generateAttackerPatterns(random);

        // 5. 내부자 위협 시나리오 패턴 생성
        log.info("\n[5단계] 내부자 위협 시나리오 패턴 생성");
        totalPatterns += generateInsiderThreatPatterns(random);

        // 6. Brute Force 공격 패턴 생성
        log.info("\n[6단계] Brute Force 공격 패턴 생성");
        totalPatterns += generateBruteForcePatterns(random);

        // 7. Credential Stuffing 공격 패턴 생성
        log.info("\n[7단계] Credential Stuffing 공격 패턴 생성");
        totalPatterns += generateCredentialStuffingPatterns(random);

        // 8. Bot Attack 공격 패턴 생성
        log.info("\n[8단계] Bot Attack 공격 패턴 생성");
        totalPatterns += generateBotAttackPatterns(random);

        // 9. Session Hijacking 공격 패턴 생성
        log.info("\n[9단계] Session Hijacking 공격 패턴 생성");
        totalPatterns += generateSessionHijackingPatterns(random);

        // 10. Impossible Travel 공격 패턴 생성
        log.info("\n[10단계] Impossible Travel 공격 패턴 생성");
        totalPatterns += generateImpossibleTravelPatterns(random);

        log.info("\n========================================");
        log.info("Vector Store 초기화 완료!");
        log.info("총 {}개의 행동 패턴 저장됨", totalPatterns);
        log.info("========================================");

        // ✅ NEW: Redis BaselineVector 초기화
        log.info("\n[11단계] Redis BaselineVector 초기화");
        initializeBaselineVectors();

        // ✅ NEW: Redis 초기화 검증
        log.info("\n[12단계] Redis 초기화 검증");
        verifyRedisInitialization();

        log.info("");
        log.info("패턴 분류:");
        log.info("- 정상 활동 패턴");
        log.info("- @Protectable 정상 접근 패턴");
        log.info("- 경계선 패턴 (월말 정산, 긴급 상황)");
        log.info("- 공격자 패턴 (계정 탈취 시나리오)");
        log.info("- 내부자 위협 패턴");
        log.info("- Brute Force 공격 패턴");
        log.info("- Credential Stuffing 공격 패턴");
        log.info("- Bot Attack 공격 패턴");
        log.info("- Session Hijacking 공격 패턴");
        log.info("- Impossible Travel 공격 패턴");
        log.info("✅ Redis BaselineVector 초기화 완료");
        log.info("");
        log.info("이제 다음을 수행할 수 있습니다:");
        log.info("1. 테스트 실행: TEST-EXECUTION-GUIDE.md 참조");
        log.info("2. Redis 확인: redis-cli KEYS \"security:baseline:vector:*\"");
        log.info("========================================");

        // 프로그램 종료
        System.exit(0);
    }

    /**
     * 정상 활동 패턴 생성 (시퀀스 패턴 포함)
     */
    private int generateNormalPatterns(int days, Random random) {
        int patterns = 0;
        Map<String, BehavioralAnalysisContext> userContexts = new HashMap<>();

        // 각 사용자별로 30일간의 정상 행동 패턴 생성
        for (String userId : USERS) {
            log.info("  사용자 {} 일반 활동 패턴 생성 중 (시퀀스 포함)...", userId);

            // 30일간의 데이터
            for (int day = 0; day < days; day++) {
                LocalDateTime baseTime = LocalDateTime.now().minusDays(days - day);

                // 사용자별 컨텍스트 초기화 또는 재사용
                BehavioralAnalysisContext userContext = userContexts.computeIfAbsent(userId,
                    k -> createInitialContext(k));

                // 업무 시간 (9시-18시) 동안의 활동
                for (int hour = 9; hour <= 17; hour++) {
                    // 시간당 2-5개의 활동
                    int activitiesPerHour = 2 + random.nextInt(4);

                    for (int activity = 0; activity < activitiesPerHour; activity++) {
                        LocalDateTime activityTime = baseTime
                            .withHour(hour)
                            .withMinute(random.nextInt(60))
                            .withSecond(random.nextInt(60));

                        String selectedActivity = selectActivityForUser(userId, random);
                        String ipAddress = generateNormalIpAddress(userId);

                        // 새로운 컨텍스트 생성 (이전 컨텍스트에서 시퀀스 정보 복사)
                        BehavioralAnalysisContext context = new BehavioralAnalysisContext();
                        context.setUserId(userId);
                        context.setOrganizationId("contexa");
                        context.setCurrentActivity(selectedActivity);
                        context.setRemoteIp(ipAddress);

                        // 디바이스 정보 설정
                        String deviceInfo = generateDeviceInfo(userId, random);
                        context.setUserAgent(deviceInfo);
                        context.setBrowserInfo("Chrome 120.0");
                        context.setOsInfo("Windows 10");
                        context.setNewDevice(false);
                        context.setNewLocation(false);

                        // 시퀀스 정보 추가
                        context.addActivityToSequence(selectedActivity);
                        if (userContext.getRecentActivitySequence() != null &&
                            !userContext.getRecentActivitySequence().isEmpty()) {
                            // 이전 활동들 복사 (최대 5개)
                            List<String> prevSequence = userContext.getRecentActivitySequence();
                            int startIdx = Math.max(0, prevSequence.size() - 5);
                            for (int i = startIdx; i < prevSequence.size(); i++) {
                                context.getRecentActivitySequence().add(0, prevSequence.get(i));
                            }
                            context.setPreviousActivity(userContext.getCurrentActivity());
                        }
                        context.setLastActivityTime(activityTime);

                        // 활동 빈도 및 속도 계산
                        context.setDailyActivityCount(activitiesPerHour * 8); // 추정치
                        context.setHourlyActivityCount(activitiesPerHour);
                        context.setActivityVelocity(60.0 / (60.0 / activitiesPerHour)); // actions per minute

                        // 세션/디바이스 핑거프린트 생성
                        context.generateSessionFingerprint();
                        context.generateDeviceFingerprint();

                        // 위치 및 네트워크 정보
                        context.setGeoLocation("Seoul, Korea");
                        context.setNetworkSegment("INTERNAL");
                        context.setVpnConnection(false);
                        context.setAccessContext("업무시간_정상접근");

                        // 행동 이상 점수 (정상이므로 낮게)
                        context.setBehaviorAnomalyScore(0.1 + random.nextDouble() * 0.2);
                        context.setHasRiskyPattern(false);
                        context.setRiskCategory("LOW");

                        // 메타데이터로 추가 정보 저장
                        context.addMetadata("documentType", "behavior");  // BehaviorVectorService 필터용
                        context.addMetadata("eventId", UUID.randomUUID().toString());  // Layer2 findSimilarEvents용
                        context.addMetadata("timestamp", activityTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));  // Layer2/Layer3용
                        context.addMetadata("accessTime", activityTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                        context.addMetadata("deviceInfo", deviceInfo);
                        context.addMetadata("locationInfo", "Seoul, Korea");
                        context.addMetadata("dayOfWeek", activityTime.getDayOfWeek().toString());
                        context.addMetadata("hour", String.valueOf(activityTime.getHour()));
                        context.addMetadata("patternType", "normal_activity");
                        context.addMetadata("riskLevel", "low");
                        context.addMetadata("sequencePattern", context.getSequencePattern());
                        context.addMetadata("sessionFingerprint", context.getSessionFingerprint());
                        context.addMetadata("deviceFingerprint", context.getDeviceFingerprint());
                        // Layer3 ThreatIntelligence용 - 정상 패턴은 위협 액터 없음
                        context.addMetadata("threatActor", "NONE");
                        context.addMetadata("campaignId", "NONE");
                        context.addMetadata("campaignName", "");
                        // Layer3 HistoricalContext용
                        context.addMetadata("incidentId", "");  // 정상 활동은 인시던트 아님
                        context.addMetadata("mitreTactic", "");
                        // Layer3 SystemContext용
                        context.addMetadata("assetCriticality", "LOW");

                        // Vector Store에 저장
                        behaviorVectorService.storeBehavior(context);
                        patterns++;

                        // 현재 컨텍스트를 사용자 컨텍스트로 업데이트
                        userContexts.put(userId, context);

                        if (patterns % 50 == 0) {
                            log.debug("    {}개 패턴 저장...", patterns);
                        }
                    }
                }
            }
        }
        return patterns;
    }

    /**
     * @Protectable 리소스 정상 접근 패턴 생성
     */
    private int generateProtectableNormalPatterns(int days, Random random) {
        int patterns = 0;

        for (String userId : USERS) {
            List<ProtectableAccessPattern> userPatterns = USER_PROTECTABLE_PATTERNS.get(userId);
            if (userPatterns == null) continue;

            log.info("  사용자 {} @Protectable 접근 패턴 생성 중...", userId);

            for (int day = 0; day < days; day++) {
                LocalDateTime baseTime = LocalDateTime.now().minusDays(days - day);

                for (ProtectableAccessPattern pattern : userPatterns) {
                    if (pattern.dailyFrequency == 0) continue;  // 접근 권한 없음

                    // 일일 접근 빈도에 따라 패턴 생성
                    for (int access = 0; access < pattern.dailyFrequency; access++) {
                        LocalDateTime accessTime = generateAccessTime(
                            baseTime, pattern.accessTimeRange, random);

                        BehavioralAnalysisContext context = new BehavioralAnalysisContext();
                        context.setUserId(userId);
                        context.setOrganizationId("contexa");
                        context.setCurrentActivity("ProtectableDataService." + pattern.methodName);
                        context.setRemoteIp(generateNormalIpAddress(userId));

                        // @Protectable 관련 메타데이터
                        context.addMetadata("documentType", "behavior");
                        context.addMetadata("eventId", UUID.randomUUID().toString());
                        context.addMetadata("timestamp", accessTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                        context.addMetadata("accessTime", accessTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                        context.addMetadata("resourceType", "@Protectable");
                        context.addMetadata("methodName", pattern.methodName);
                        context.addMetadata("accessPurpose", pattern.accessPurpose);
                        context.addMetadata("bulkSize", String.valueOf(
                            pattern.maxBulkSize > 1 ? random.nextInt(pattern.maxBulkSize) + 1 : 1));
                        context.addMetadata("deviceInfo", "Windows 10, Chrome 120.0");
                        context.addMetadata("locationInfo", "Seoul, Korea");
                        context.addMetadata("patternType", "protectable_normal");
                        context.addMetadata("riskLevel", "low");
                        context.addMetadata("threatActor", "NONE");
                        context.addMetadata("campaignId", "NONE");
                        context.addMetadata("campaignName", "");
                        context.addMetadata("incidentId", "");
                        context.addMetadata("mitreTactic", "");
                        context.addMetadata("assetCriticality", "MEDIUM");

                        behaviorVectorService.storeBehavior(context);
                        patterns++;
                    }
                }
            }
        }
        return patterns;
    }

    /**
     * 경계선 패턴 생성 (정상이지만 주의 필요한 경우)
     */
    private int generateBorderlinePatterns(Random random) {
        int patterns = 0;

        // 월말 정산 - finance_manager의 대량 조회
        log.info("  월말 정산 패턴 생성...");
        for (int i = 0; i < 3; i++) {  // 최근 3개월 월말
            LocalDateTime monthEnd = LocalDateTime.now().minusMonths(i).withDayOfMonth(28);

            BehavioralAnalysisContext context = new BehavioralAnalysisContext();
            context.setUserId("finance_manager");
            context.setOrganizationId("contexa");
            context.setCurrentActivity("ProtectableDataService.getAllCustomerData");
            context.setRemoteIp(generateNormalIpAddress("finance_manager"));

            LocalDateTime monthEndTime = monthEnd.withHour(18);
            context.addMetadata("documentType", "behavior");
            context.addMetadata("eventId", UUID.randomUUID().toString());
            context.addMetadata("timestamp", monthEndTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("accessTime", monthEndTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("resourceType", "@Protectable");
            context.addMetadata("methodName", "getAllCustomerData");
            context.addMetadata("accessPurpose", "월말정산");
            context.addMetadata("bulkSize", "1000");
            context.addMetadata("patternType", "borderline_monthend");
            context.addMetadata("riskLevel", "medium");
            context.addMetadata("specialContext", "month_end_settlement");
            // Layer3 ThreatIntelligence용 - borderline (정당한 이유)
            context.addMetadata("threatActor", "NONE");
            context.addMetadata("campaignId", "NONE");
            context.addMetadata("campaignName", "");
            context.addMetadata("iocIndicator", "bulk_access,legitimate_business");
            // Layer3 HistoricalContext용
            context.addMetadata("incidentId", "");
            context.addMetadata("mitreTactic", "");
            // Layer3 SystemContext용
            context.addMetadata("assetCriticality", "MEDIUM");

            behaviorVectorService.storeBehavior(context);
            patterns++;
        }

        // 긴급 패치 - dev_lead의 야간 접근
        log.info("  긴급 패치 패턴 생성...");
        for (int i = 0; i < 2; i++) {
            LocalDateTime nightTime = LocalDateTime.now().minusDays(random.nextInt(30))
                .withHour(22 + random.nextInt(3));

            BehavioralAnalysisContext context = new BehavioralAnalysisContext();
            context.setUserId("dev_lead");
            context.setOrganizationId("contexa");
            context.setCurrentActivity("ProtectableDataService.updateCustomerData");
            context.setRemoteIp(generateNormalIpAddress("dev_lead"));

            context.addMetadata("documentType", "behavior");
            context.addMetadata("eventId", UUID.randomUUID().toString());
            context.addMetadata("timestamp", nightTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("accessTime", nightTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("resourceType", "@Protectable");
            context.addMetadata("methodName", "updateCustomerData");
            context.addMetadata("accessPurpose", "긴급패치");
            context.addMetadata("patternType", "borderline_emergency");
            context.addMetadata("riskLevel", "medium");
            context.addMetadata("specialContext", "emergency_patch");
            // Layer3 ThreatIntelligence용 - borderline (정당한 이유)
            context.addMetadata("threatActor", "NONE");
            context.addMetadata("campaignId", "NONE");
            context.addMetadata("campaignName", "");
            context.addMetadata("iocIndicator", "after_hours,legitimate_emergency");
            // Layer3 HistoricalContext용
            context.addMetadata("incidentId", "");
            context.addMetadata("mitreTactic", "");
            // Layer3 SystemContext용
            context.addMetadata("assetCriticality", "MEDIUM");

            behaviorVectorService.storeBehavior(context);
            patterns++;
        }

        // 시스템 점검 - admin의 전체 데이터 접근
        log.info("  시스템 점검 패턴 생성...");
        LocalDateTime maintenance = LocalDateTime.now().minusDays(7).withHour(3);

        BehavioralAnalysisContext context = new BehavioralAnalysisContext();
        context.setUserId("admin");
        context.setOrganizationId("contexa");
        context.setCurrentActivity("ProtectableDataService.getAllCustomerData");
        context.setRemoteIp(generateNormalIpAddress("admin"));

        context.addMetadata("documentType", "behavior");
        context.addMetadata("eventId", UUID.randomUUID().toString());
        context.addMetadata("timestamp", maintenance.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        context.addMetadata("accessTime", maintenance.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        context.addMetadata("resourceType", "@Protectable");
        context.addMetadata("methodName", "getAllCustomerData");
        context.addMetadata("accessPurpose", "시스템점검");
        context.addMetadata("bulkSize", "all");
        context.addMetadata("patternType", "borderline_maintenance");
        context.addMetadata("riskLevel", "medium");
        context.addMetadata("specialContext", "system_maintenance");
        // Layer3 ThreatIntelligence용 - borderline (정당한 이유)
        context.addMetadata("threatActor", "NONE");
        context.addMetadata("campaignId", "NONE");
        context.addMetadata("campaignName", "");
        context.addMetadata("iocIndicator", "bulk_access,legitimate_maintenance");
        // Layer3 HistoricalContext용
        context.addMetadata("incidentId", "");
        context.addMetadata("mitreTactic", "");
        // Layer3 SystemContext용
        context.addMetadata("assetCriticality", "MEDIUM");

        behaviorVectorService.storeBehavior(context);
        patterns++;

        return patterns;
    }

    /**
     * 공격자 시나리오 패턴 생성 (계정 탈취)
     */
    private int generateAttackerPatterns(Random random) {
        int patterns = 0;

        // admin 계정 탈취 시나리오
        log.info("  공격자의 admin 계정 탈취 시나리오...");
        // SimulationConfig에서 의심스러운 IP 주소 가져오기
        List<String> suspiciousIPs = simulationConfig.getAttackIps().getSuspicious();
        String[] attackerIPs = suspiciousIPs != null && suspiciousIPs.size() >= 3
                ? new String[]{suspiciousIPs.get(0), suspiciousIPs.get(1), suspiciousIPs.get(2)}
                : new String[]{"45.142.123.45", "185.220.100.252", "23.129.64.131"};

        for (String attackerIP : attackerIPs) {
            // 새벽 시간 대량 데이터 접근
            LocalDateTime attackTime = LocalDateTime.now().minusDays(1)
                .withHour(3).withMinute(random.nextInt(60));

            BehavioralAnalysisContext attackContext = null;

            // 1. getAllCustomerData 반복 호출 (데이터 탈취)
            for (int i = 0; i < 5; i++) {
                BehavioralAnalysisContext context = new BehavioralAnalysisContext();
                context.setUserId("admin");  // 탈취된 계정
                context.setOrganizationId("contexa");
                context.setCurrentActivity("ProtectableDataService.getAllCustomerData");
                context.setRemoteIp(attackerIP);  // 외부 IP

                // 공격자의 빠른 시퀀스 패턴
                if (attackContext != null) {
                    context.setPreviousActivity(attackContext.getCurrentActivity());
                    // 짧은 시간 간격 표현
                    context.setTimeSinceLastActivity(Duration.ofSeconds(5 + random.nextInt(10)));
                    // 공격 시퀀스 복사
                    if (attackContext.getRecentActivitySequence() != null) {
                        List<String> prevSeq = attackContext.getRecentActivitySequence();
                        for (int j = Math.max(0, prevSeq.size() - 3); j < prevSeq.size(); j++) {
                            context.addActivityToSequence(prevSeq.get(j));
                        }
                    }
                }
                context.addActivityToSequence("ProtectableDataService.getAllCustomerData");

                // 공격자 디바이스 정보 (다른 OS/브라우저)
                context.setUserAgent("curl/7.68.0");
                context.setBrowserInfo("curl");
                context.setOsInfo("Linux");
                context.setNewDevice(true);  // 새로운 디바이스
                context.setNewLocation(true); // 새로운 위치

                // 빠른 활동 속도 (공격자 특징)
                context.setActivityVelocity(120.0); // 분당 120개 활동 (비정상적으로 빠름)
                context.setHourlyActivityCount(300); // 시간당 300개 (비정상)

                // 핑거프린트 생성
                context.generateSessionFingerprint();
                context.generateDeviceFingerprint();

                // 위치 및 네트워크 정보
                context.setGeoLocation("Russia");
                context.setNetworkSegment("EXTERNAL");
                context.setVpnConnection(true); // VPN 사용
                context.setAccessContext("외부_공격_탈취");

                // 높은 이상 점수
                context.setBehaviorAnomalyScore(0.9 + random.nextDouble() * 0.1);
                context.addAnomalyIndicator("foreign_ip");
                context.addAnomalyIndicator("unusual_time");
                context.addAnomalyIndicator("repeated_bulk_access");
                context.addAnomalyIndicator("new_device");
                context.addAnomalyIndicator("new_location");
                context.addAnomalyIndicator("vpn_detected");
                context.setRiskCategory("CRITICAL");

                LocalDateTime currentAttackTime = attackTime.plusMinutes(i * 2);
                context.addMetadata("documentType", "behavior");
                context.addMetadata("eventId", UUID.randomUUID().toString());
                context.addMetadata("timestamp", currentAttackTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                context.addMetadata("accessTime", currentAttackTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                context.addMetadata("resourceType", "@Protectable");
                context.addMetadata("methodName", "getAllCustomerData");
                context.addMetadata("accessPurpose", "data_exfiltration");
                context.addMetadata("bulkSize", "all");
                context.addMetadata("patternType", "attack_account_takeover");
                context.addMetadata("riskLevel", "critical");
                context.addMetadata("anomaly", "foreign_ip,unusual_time,repeated_bulk_access");
                context.addMetadata("deviceInfo", "Linux, curl/7.68.0");
                context.addMetadata("locationInfo", "Russia");
                context.addMetadata("sequencePattern", context.getSequencePattern());
                context.addMetadata("sessionFingerprint", context.getSessionFingerprint());
                context.addMetadata("anomalyIndicators", String.join(",", context.getAnomalyIndicators()));
                // Layer3 ThreatIntelligence용
                context.addMetadata("threatActor", "APT28");
                context.addMetadata("campaignId", "CAMPAIGN-001");
                context.addMetadata("campaignName", "Data Exfiltration Campaign 2024");
                context.addMetadata("iocIndicator", attackerIP + ",curl/7.68.0,vpn_detected");
                // Layer3 HistoricalContext용
                context.addMetadata("incidentId", "INC-" + UUID.randomUUID().toString().substring(0, 8));
                context.addMetadata("mitreTactic", "TA0010-Exfiltration");
                // Layer3 SystemContext용
                context.addMetadata("assetCriticality", "CRITICAL");

                behaviorVectorService.storeBehavior(context);
                patterns++;
                attackContext = context;
            }

            // 2. deleteCustomerData 시도 (파괴적 공격)
            BehavioralAnalysisContext deleteContext = new BehavioralAnalysisContext();
            deleteContext.setUserId("admin");
            deleteContext.setOrganizationId("contexa");
            deleteContext.setCurrentActivity("ProtectableDataService.deleteCustomerData");
            deleteContext.setRemoteIp(attackerIP);

            // 이전 공격 시퀀스와 연결
            if (attackContext != null) {
                deleteContext.setPreviousActivity(attackContext.getCurrentActivity());
                deleteContext.setTimeSinceLastActivity(Duration.ofSeconds(30));
                // 공격 시퀀스 계승
                for (String activity : attackContext.getRecentActivitySequence()) {
                    deleteContext.addActivityToSequence(activity);
                }
            }
            deleteContext.addActivityToSequence("ProtectableDataService.deleteCustomerData");

            // 공격자 디바이스 정보 유지
            deleteContext.setUserAgent("curl/7.68.0");
            deleteContext.setBrowserInfo("curl");
            deleteContext.setOsInfo("Linux");
            deleteContext.setNewDevice(true);
            deleteContext.setNewLocation(true);

            // 핑거프린트 생성
            deleteContext.generateSessionFingerprint();
            deleteContext.generateDeviceFingerprint();

            deleteContext.setGeoLocation("Russia");
            deleteContext.setNetworkSegment("EXTERNAL");
            deleteContext.setVpnConnection(true);
            deleteContext.setAccessContext("외부_공격_파괴");

            // 최고 위험 점수
            deleteContext.setBehaviorAnomalyScore(0.99);
            deleteContext.addAnomalyIndicator("rare_operation");
            deleteContext.addAnomalyIndicator("foreign_ip");
            deleteContext.addAnomalyIndicator("unusual_time");
            deleteContext.addAnomalyIndicator("destructive_action");
            deleteContext.setRiskCategory("CRITICAL");

            deleteContext.addMetadata("accessTime", attackTime.plusMinutes(12)
                .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            deleteContext.addMetadata("resourceType", "@Protectable");
            deleteContext.addMetadata("methodName", "deleteCustomerData");
            deleteContext.addMetadata("accessPurpose", "destructive_attack");
            deleteContext.addMetadata("patternType", "attack_destructive");
            deleteContext.addMetadata("riskLevel", "critical");
            deleteContext.addMetadata("anomaly", "rare_operation,foreign_ip,unusual_time");
            deleteContext.addMetadata("sequencePattern", deleteContext.getSequencePattern());
            deleteContext.addMetadata("anomalyIndicators", String.join(",", deleteContext.getAnomalyIndicators()));

            behaviorVectorService.storeBehavior(deleteContext);
            patterns++;
        }

        return patterns;
    }

    /**
     * 내부자 위협 시나리오 패턴 생성
     */
    private int generateInsiderThreatPatterns(Random random) {
        int patterns = 0;

        // 시나리오 1: finance_manager가 평소보다 많은 데이터 접근
        log.info("  내부자 위협: finance_manager 대량 데이터 유출 시도...");
        LocalDateTime insiderTime = LocalDateTime.now().minusDays(2).withHour(17).withMinute(45);

        BehavioralAnalysisContext prevContext = null;
        List<String> suspiciousSequence = new ArrayList<>();
        suspiciousSequence.add("결재 문서 확인");  // 정상 행동 위장
        suspiciousSequence.add("재무 보고서 조회");  // 정상 행동 위장

        for (int i = 0; i < 10; i++) {  // 연속적인 대량 조회
            BehavioralAnalysisContext context = new BehavioralAnalysisContext();
            context.setUserId("finance_manager");
            context.setOrganizationId("contexa");
            context.setCurrentActivity("ProtectableDataService.getAllCustomerData");
            context.setRemoteIp(generateNormalIpAddress("finance_manager"));  // 정상 IP

            // 시퀀스 패턴 구축 (평소와 다른 패턴)
            if (prevContext != null) {
                context.setPreviousActivity(prevContext.getCurrentActivity());
                // 빠른 반복 접근 (짧은 간격)
                context.setTimeSinceLastActivity(Duration.ofMinutes(3));
                // 의심스러운 시퀀스 저장
                for (String seq : suspiciousSequence) {
                    context.addActivityToSequence(seq);
                }
            }
            context.addActivityToSequence("ProtectableDataService.getAllCustomerData");

            // 정상 디바이스 사용 (내부자 특징)
            context.setUserAgent("Windows 10, Chrome 120.0");
            context.setBrowserInfo("Chrome 120.0");
            context.setOsInfo("Windows 10");
            context.setNewDevice(false);  // 기존 디바이스
            context.setNewLocation(false); // 기존 위치

            // 비정상적으로 높은 활동 빈도
            context.setActivityVelocity(20.0); // 분당 20개 (평소보다 10배)
            context.setHourlyActivityCount(100); // 시간당 100개 (평소보다 많음)
            context.setDailyActivityCount(200); // 하루 200개 (비정상)

            // 핑거프린트 생성
            context.generateSessionFingerprint();
            context.generateDeviceFingerprint();

            // 정상 위치이지만 의심스러운 시간
            context.setGeoLocation("Seoul, Korea");
            context.setNetworkSegment("INTERNAL");
            context.setVpnConnection(false);
            context.setAccessContext("퇴근시간_대량조회");

            // 중간 위험 점수 (내부자이므로 완전히 높지는 않음)
            context.setBehaviorAnomalyScore(0.7 + random.nextDouble() * 0.2);
            context.addAnomalyIndicator("excessive_volume");
            context.addAnomalyIndicator("repeated_access");
            context.addAnomalyIndicator("end_of_day");
            context.addAnomalyIndicator("unusual_frequency");
            context.setRiskCategory("HIGH");

            LocalDateTime currentInsiderTime = insiderTime.plusMinutes(i * 3);
            context.addMetadata("documentType", "behavior");
            context.addMetadata("eventId", UUID.randomUUID().toString());
            context.addMetadata("timestamp", currentInsiderTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("accessTime", currentInsiderTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("resourceType", "@Protectable");
            context.addMetadata("methodName", "getAllCustomerData");
            context.addMetadata("accessPurpose", "suspicious_export");
            context.addMetadata("bulkSize", "5000");
            context.addMetadata("patternType", "insider_threat_exfiltration");
            context.addMetadata("riskLevel", "high");
            context.addMetadata("anomaly", "excessive_volume,repeated_access,end_of_day");
            context.addMetadata("deviceInfo", "Windows 10, Chrome 120.0");
            context.addMetadata("locationInfo", "Seoul, Korea");
            context.addMetadata("sequencePattern", context.getSequencePattern());
            context.addMetadata("activityVelocity", String.valueOf(context.getActivityVelocity()));
            // Layer3 ThreatIntelligence용
            context.addMetadata("threatActor", "Insider-finance_manager");
            context.addMetadata("campaignId", "CAMPAIGN-INS-001");
            context.addMetadata("campaignName", "Insider Data Exfiltration 2024");
            context.addMetadata("iocIndicator", "excessive_volume,end_of_day,unusual_frequency");
            // Layer3 HistoricalContext용
            context.addMetadata("incidentId", "INC-INS-" + UUID.randomUUID().toString().substring(0, 8));
            context.addMetadata("mitreTactic", "TA0010-Exfiltration");
            // Layer3 SystemContext용
            context.addMetadata("assetCriticality", "HIGH");

            behaviorVectorService.storeBehavior(context);
            patterns++;
            prevContext = context;
        }

        // 시나리오 2: dev_lead가 권한 없는 작업 시도
        log.info("  내부자 위협: dev_lead 권한 상승 시도...");
        LocalDateTime privilegeEscalation = LocalDateTime.now().minusDays(3).withHour(16);

        // deleteCustomerData 시도 (권한 없음)
        BehavioralAnalysisContext context = new BehavioralAnalysisContext();
        context.setUserId("dev_lead");
        context.setOrganizationId("contexa");
        context.setCurrentActivity("ProtectableDataService.deleteCustomerData");
        context.setRemoteIp(generateNormalIpAddress("dev_lead"));

        context.addMetadata("documentType", "behavior");
        context.addMetadata("eventId", UUID.randomUUID().toString());
        context.addMetadata("timestamp", privilegeEscalation.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        context.addMetadata("accessTime", privilegeEscalation.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        context.addMetadata("resourceType", "@Protectable");
        context.addMetadata("methodName", "deleteCustomerData");
        context.addMetadata("accessPurpose", "unauthorized_attempt");
        context.addMetadata("patternType", "insider_threat_privilege_escalation");
        context.addMetadata("riskLevel", "high");
        context.addMetadata("anomaly", "unauthorized_operation,role_violation");
        // Layer3 ThreatIntelligence용
        context.addMetadata("threatActor", "Insider-dev_lead");
        context.addMetadata("campaignId", "CAMPAIGN-INS-002");
        context.addMetadata("campaignName", "Privilege Escalation Attempt 2024");
        context.addMetadata("iocIndicator", "unauthorized_operation,role_violation");
        // Layer3 HistoricalContext용
        context.addMetadata("incidentId", "INC-PE-" + UUID.randomUUID().toString().substring(0, 8));
        context.addMetadata("mitreTactic", "TA0004-PrivilegeEscalation");
        // Layer3 SystemContext용
        context.addMetadata("assetCriticality", "CRITICAL");

        behaviorVectorService.storeBehavior(context);
        patterns++;

        // 시나리오 3: op_user가 업무 시간 외 민감 데이터 접근
        log.info("  내부자 위협: op_user 업무 시간 외 접근...");
        LocalDateTime afterHours = LocalDateTime.now().minusDays(4).withHour(23);

        BehavioralAnalysisContext nightPrevContext = null;
        for (int i = 0; i < 20; i++) {  // 밤에 연속 조회
            BehavioralAnalysisContext nightContext = new BehavioralAnalysisContext();
            nightContext.setUserId("op_user");
            nightContext.setOrganizationId("contexa");
            nightContext.setCurrentActivity("ProtectableDataService.getCustomerData");
            nightContext.setRemoteIp(generateNormalIpAddress("op_user"));

            // 비정상 시간대 시퀀스 패턴
            if (nightPrevContext != null) {
                nightContext.setPreviousActivity(nightPrevContext.getCurrentActivity());
                nightContext.setTimeSinceLastActivity(Duration.ofMinutes(2)); // 빠른 반복
                // 이전 시퀀스 복사
                List<String> prevSeq = nightPrevContext.getRecentActivitySequence();
                if (prevSeq != null && !prevSeq.isEmpty()) {
                    for (int j = Math.max(0, prevSeq.size() - 3); j < prevSeq.size(); j++) {
                        nightContext.addActivityToSequence(prevSeq.get(j));
                    }
                }
            }
            nightContext.addActivityToSequence("ProtectableDataService.getCustomerData");

            // 정상 디바이스이지만 비정상 시간
            nightContext.setUserAgent("Windows 10, Chrome 120.0");
            nightContext.setBrowserInfo("Chrome 120.0");
            nightContext.setOsInfo("Windows 10");
            nightContext.setNewDevice(false);
            nightContext.setNewLocation(false);

            // 비정상 시간대 활동
            nightContext.setActivityVelocity(30.0); // 분당 30개 (밤에 비정상)
            nightContext.setHourlyActivityCount(40); // 시간당 40개

            nightContext.generateSessionFingerprint();
            nightContext.generateDeviceFingerprint();

            nightContext.setGeoLocation("Seoul, Korea");
            nightContext.setNetworkSegment("INTERNAL");
            nightContext.setVpnConnection(false);
            nightContext.setAccessContext("야간_비정상_접근");

            nightContext.setBehaviorAnomalyScore(0.75 + random.nextDouble() * 0.15);
            nightContext.addAnomalyIndicator("after_hours");
            nightContext.addAnomalyIndicator("excessive_frequency");
            nightContext.addAnomalyIndicator("unusual_time_pattern");
            nightContext.setRiskCategory("HIGH");

            LocalDateTime currentNightTime = afterHours.plusMinutes(i * 2);
            nightContext.addMetadata("documentType", "behavior");
            nightContext.addMetadata("eventId", UUID.randomUUID().toString());
            nightContext.addMetadata("timestamp", currentNightTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            nightContext.addMetadata("accessTime", currentNightTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            nightContext.addMetadata("resourceType", "@Protectable");
            nightContext.addMetadata("methodName", "getCustomerData");
            nightContext.addMetadata("accessPurpose", "suspicious_access");
            nightContext.addMetadata("patternType", "insider_threat_after_hours");
            nightContext.addMetadata("riskLevel", "high");
            nightContext.addMetadata("anomaly", "after_hours,excessive_frequency");
            nightContext.addMetadata("sequencePattern", nightContext.getSequencePattern());
            // Layer3 ThreatIntelligence용
            nightContext.addMetadata("threatActor", "Insider-cs_agent");
            nightContext.addMetadata("campaignId", "CAMPAIGN-INS-003");
            nightContext.addMetadata("campaignName", "After Hours Data Access 2024");
            nightContext.addMetadata("iocIndicator", "after_hours,excessive_frequency");
            // Layer3 HistoricalContext용
            nightContext.addMetadata("incidentId", "INC-AH-" + UUID.randomUUID().toString().substring(0, 8));
            nightContext.addMetadata("mitreTactic", "TA0009-Collection");
            // Layer3 SystemContext용
            nightContext.addMetadata("assetCriticality", "MEDIUM");

            behaviorVectorService.storeBehavior(nightContext);
            patterns++;
            nightPrevContext = nightContext;
        }

        return patterns;
    }

    /**
     * Brute Force 공격 패턴 생성
     * 동일 계정에 대한 반복적인 로그인 실패 시도
     */
    private int generateBruteForcePatterns(Random random) {
        int patterns = 0;

        log.info("  Brute Force 공격 패턴 생성...");

        // admin 계정 대상 브루트포스
        String targetUsername = "admin";
        String attackerIP = simulationConfig.getAttackIps().getSuspicious().get(0);
        LocalDateTime attackStartTime = LocalDateTime.now().minusDays(5).withHour(2);

        // 짧은 시간 내 100회 로그인 시도 패턴 생성
        for (int attempt = 0; attempt < 100; attempt++) {
            BehavioralAnalysisContext context = new BehavioralAnalysisContext();
            context.setUserId(targetUsername);
            context.setOrganizationId("contexa");
            context.setCurrentActivity("LOGIN_ATTEMPT_FAILED");
            context.setRemoteIp(attackerIP);

            // 공격자 User-Agent (봇)
            context.setUserAgent("python-requests/2.31.0");
            context.setBrowserInfo("python-requests");
            context.setOsInfo("Linux");
            context.setNewDevice(true);
            context.setNewLocation(true);

            // 매우 빠른 시도 간격 (1초)
            LocalDateTime attemptTime = attackStartTime.plusSeconds(attempt);
            context.setLastActivityTime(attemptTime);
            context.setActivityVelocity(60.0); // 분당 60회

            // 핑거프린트 생성
            context.generateSessionFingerprint();
            context.generateDeviceFingerprint();

            // 위치 및 네트워크
            context.setGeoLocation("Unknown");
            context.setNetworkSegment("EXTERNAL");
            context.setVpnConnection(false);
            context.setAccessContext("브루트포스_공격");

            // 높은 이상 점수
            double riskScore = calculateContextRiskScore(context);
            context.setBehaviorAnomalyScore(riskScore / 100.0);
            context.addAnomalyIndicator("rapid_login_attempts");
            context.addAnomalyIndicator("foreign_ip");
            context.addAnomalyIndicator("bot_user_agent");
            context.addAnomalyIndicator("repeated_failures");
            context.setRiskCategory("CRITICAL");

            // 메타데이터
            context.addMetadata("documentType", "behavior");
            context.addMetadata("eventId", UUID.randomUUID().toString());
            context.addMetadata("timestamp", attemptTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("accessTime", attemptTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("attackType", "brute_force");
            context.addMetadata("attemptNumber", String.valueOf(attempt + 1));
            context.addMetadata("totalAttempts", "100");
            context.addMetadata("patternType", "attack_brute_force");
            context.addMetadata("riskLevel", "critical");
            context.addMetadata("targetUsername", targetUsername);
            // Layer3 ThreatIntelligence용
            context.addMetadata("threatActor", "Botnet-Operator");
            context.addMetadata("campaignId", "CAMPAIGN-BF-001");
            context.addMetadata("campaignName", "Brute Force Attack Wave 2024");
            context.addMetadata("iocIndicator", attackerIP + ",python-requests,rapid_attempts");
            // Layer3 HistoricalContext용
            context.addMetadata("incidentId", "INC-BF-" + UUID.randomUUID().toString().substring(0, 8));
            context.addMetadata("mitreTactic", "TA0006-CredentialAccess");
            // Layer3 SystemContext용
            context.addMetadata("assetCriticality", "HIGH");

            behaviorVectorService.storeBehavior(context);
            patterns++;
        }

        return patterns;
    }

    /**
     * Credential Stuffing 공격 패턴 생성
     * 유출된 다양한 계정으로 로그인 시도
     */
    private int generateCredentialStuffingPatterns(Random random) {
        int patterns = 0;

        log.info("  Credential Stuffing 공격 패턴 생성...");

        // SimulationConfig에서 크리덴셜 목록 가져오기
        List<SimulationConfig.AttackPatterns.CredentialStuffing.Credential> credentials =
                simulationConfig.getAttackPatterns().getCredentialStuffing().getAttempts();

        String attackerIP = simulationConfig.getAttackIps().getSuspicious().get(1);
        LocalDateTime attackTime = LocalDateTime.now().minusDays(4).withHour(3);

        for (int i = 0; i < credentials.size(); i++) {
            SimulationConfig.AttackPatterns.CredentialStuffing.Credential cred = credentials.get(i);

            BehavioralAnalysisContext context = new BehavioralAnalysisContext();
            context.setUserId(cred.getUsername());
            context.setOrganizationId("contexa");
            context.setCurrentActivity("LOGIN_ATTEMPT_CREDENTIAL_STUFFING");
            context.setRemoteIp(attackerIP);

            // 공격자 User-Agent
            context.setUserAgent("Mozilla/5.0 (automated)");
            context.setBrowserInfo("automated");
            context.setOsInfo("Linux");
            context.setNewDevice(true);
            context.setNewLocation(true);

            LocalDateTime attemptTime = attackTime.plusSeconds(i * 5);
            context.setLastActivityTime(attemptTime);
            context.setActivityVelocity(12.0); // 분당 12회

            context.generateSessionFingerprint();
            context.generateDeviceFingerprint();

            context.setGeoLocation("Russia");
            context.setNetworkSegment("EXTERNAL");
            context.setVpnConnection(true);
            context.setAccessContext("크리덴셜_스터핑");

            double riskScore = calculateContextRiskScore(context);
            context.setBehaviorAnomalyScore(riskScore / 100.0);
            context.addAnomalyIndicator("multiple_account_attempts");
            context.addAnomalyIndicator("foreign_ip");
            context.addAnomalyIndicator("vpn_detected");
            context.setRiskCategory("HIGH");

            context.addMetadata("documentType", "behavior");
            context.addMetadata("eventId", UUID.randomUUID().toString());
            context.addMetadata("timestamp", attemptTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("accessTime", attemptTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("attackType", "credential_stuffing");
            context.addMetadata("attemptNumber", String.valueOf(i + 1));
            context.addMetadata("totalAttempts", String.valueOf(credentials.size()));
            context.addMetadata("patternType", "attack_credential_stuffing");
            context.addMetadata("riskLevel", "high");
            context.addMetadata("testUsername", cred.getUsername());
            // Layer3 ThreatIntelligence용
            context.addMetadata("threatActor", "Credential-Harvester-Group");
            context.addMetadata("campaignId", "CAMPAIGN-CS-001");
            context.addMetadata("campaignName", "Credential Stuffing Campaign 2024");
            context.addMetadata("iocIndicator", attackerIP + ",automated,vpn_detected");
            // Layer3 HistoricalContext용
            context.addMetadata("incidentId", "INC-CS-" + UUID.randomUUID().toString().substring(0, 8));
            context.addMetadata("mitreTactic", "TA0006-CredentialAccess");
            // Layer3 SystemContext용
            context.addMetadata("assetCriticality", "HIGH");

            behaviorVectorService.storeBehavior(context);
            patterns++;
        }

        return patterns;
    }

    /**
     * Bot Attack 공격 패턴 생성
     * 자동화된 봇의 빠른 연속 접근
     */
    private int generateBotAttackPatterns(Random random) {
        int patterns = 0;

        log.info("  Bot Attack 공격 패턴 생성...");

        String botIP = simulationConfig.getAttackIps().getSuspicious().get(2);
        String[] botUserAgents = simulationConfig.getUserAgents().getSuspicious().stream()
                .filter(ua -> ua.toLowerCase().contains("python") || ua.toLowerCase().contains("curl"))
                .toArray(String[]::new);

        if (botUserAgents.length == 0) {
            botUserAgents = new String[]{"python-requests/2.31.0"};
        }

        LocalDateTime botAttackTime = LocalDateTime.now().minusDays(3).withHour(4);

        // 봇의 빠른 연속 접근 패턴
        for (int i = 0; i < 50; i++) {
            BehavioralAnalysisContext context = new BehavioralAnalysisContext();
            context.setUserId("admin");
            context.setOrganizationId("contexa");
            context.setCurrentActivity("ProtectableDataService.getCustomerData");
            context.setRemoteIp(botIP);

            context.setUserAgent(botUserAgents[random.nextInt(botUserAgents.length)]);
            context.setBrowserInfo("bot");
            context.setOsInfo("Linux");
            context.setNewDevice(true);
            context.setNewLocation(true);

            LocalDateTime attemptTime = botAttackTime.plusSeconds(i * 2); // 2초 간격
            context.setLastActivityTime(attemptTime);
            context.setActivityVelocity(30.0); // 분당 30회

            context.generateSessionFingerprint();
            context.generateDeviceFingerprint();

            context.setGeoLocation("Unknown");
            context.setNetworkSegment("EXTERNAL");
            context.setVpnConnection(false);
            context.setAccessContext("봇_공격");

            double riskScore = calculateContextRiskScore(context);
            context.setBehaviorAnomalyScore(riskScore / 100.0);
            context.addAnomalyIndicator("bot_user_agent");
            context.addAnomalyIndicator("rapid_requests");
            context.addAnomalyIndicator("automated_pattern");
            context.setRiskCategory("HIGH");

            context.addMetadata("documentType", "behavior");
            context.addMetadata("eventId", UUID.randomUUID().toString());
            context.addMetadata("timestamp", attemptTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("accessTime", attemptTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("attackType", "bot_attack");
            context.addMetadata("requestNumber", String.valueOf(i + 1));
            context.addMetadata("patternType", "attack_bot");
            context.addMetadata("riskLevel", "high");
            // Layer3 ThreatIntelligence용
            context.addMetadata("threatActor", "Automated-Bot-Network");
            context.addMetadata("campaignId", "CAMPAIGN-BOT-001");
            context.addMetadata("campaignName", "Automated Bot Attack 2024");
            context.addMetadata("iocIndicator", botIP + "," + botUserAgents[random.nextInt(botUserAgents.length)] + ",rapid_requests");
            // Layer3 HistoricalContext용
            context.addMetadata("incidentId", "INC-BOT-" + UUID.randomUUID().toString().substring(0, 8));
            context.addMetadata("mitreTactic", "TA0043-Reconnaissance");
            // Layer3 SystemContext용
            context.addMetadata("assetCriticality", "HIGH");

            behaviorVectorService.storeBehavior(context);
            patterns++;
        }

        return patterns;
    }

    /**
     * Session Hijacking 공격 패턴 생성
     * 세션 도용 후 IP 변경 감지
     */
    private int generateSessionHijackingPatterns(Random random) {
        int patterns = 0;

        log.info("  Session Hijacking 공격 패턴 생성...");

        String originalIP = simulationConfig.getAttackIps().getSessionHijacking().getOriginal();
        String hijackedIP = simulationConfig.getAttackIps().getSessionHijacking().getHijacked();
        String userId = "admin";

        LocalDateTime sessionStart = LocalDateTime.now().minusDays(2).withHour(14);

        // 1. 정상 세션 활동
        for (int i = 0; i < 5; i++) {
            BehavioralAnalysisContext context = new BehavioralAnalysisContext();
            context.setUserId(userId);
            context.setOrganizationId("contexa");
            context.setCurrentActivity("대시보드 조회");
            context.setRemoteIp(originalIP);

            context.setUserAgent("Windows 10, Chrome 120.0");
            context.setBrowserInfo("Chrome 120.0");
            context.setOsInfo("Windows 10");
            context.setNewDevice(false);
            context.setNewLocation(false);

            LocalDateTime activityTime = sessionStart.plusMinutes(i * 5);
            context.setLastActivityTime(activityTime);
            context.setActivityVelocity(2.0);

            context.generateSessionFingerprint();
            context.generateDeviceFingerprint();

            context.setGeoLocation("Seoul, Korea");
            context.setNetworkSegment("INTERNAL");
            context.setVpnConnection(false);
            context.setAccessContext("정상_세션");

            context.setBehaviorAnomalyScore(0.1);
            context.setRiskCategory("LOW");

            context.addMetadata("documentType", "behavior");
            context.addMetadata("eventId", UUID.randomUUID().toString());
            context.addMetadata("timestamp", activityTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("accessTime", activityTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("sessionPhase", "normal");
            context.addMetadata("patternType", "session_normal");
            context.addMetadata("riskLevel", "low");
            // Layer3 ThreatIntelligence용 - 정상 세션
            context.addMetadata("threatActor", "NONE");
            context.addMetadata("campaignId", "NONE");
            context.addMetadata("campaignName", "");
            context.addMetadata("iocIndicator", "");
            // Layer3 HistoricalContext용
            context.addMetadata("incidentId", "");
            context.addMetadata("mitreTactic", "");
            // Layer3 SystemContext용
            context.addMetadata("assetCriticality", "LOW");

            behaviorVectorService.storeBehavior(context);
            patterns++;
        }

        // 2. 세션 하이재킹 발생 - 갑자기 IP 변경
        for (int i = 0; i < 5; i++) {
            BehavioralAnalysisContext context = new BehavioralAnalysisContext();
            context.setUserId(userId);
            context.setOrganizationId("contexa");
            context.setCurrentActivity("ProtectableDataService.getAllCustomerData");
            context.setRemoteIp(hijackedIP); // IP 변경!

            context.setUserAgent("Windows 10, Chrome 120.0"); // 동일 User-Agent
            context.setBrowserInfo("Chrome 120.0");
            context.setOsInfo("Windows 10");
            context.setNewDevice(false);
            context.setNewLocation(true); // 위치 변경 감지

            LocalDateTime hijackTime = sessionStart.plusMinutes(30 + i * 2);
            context.setLastActivityTime(hijackTime);
            context.setActivityVelocity(30.0); // 갑자기 빠른 활동

            context.generateSessionFingerprint();
            context.generateDeviceFingerprint();

            context.setGeoLocation("Russia");
            context.setNetworkSegment("EXTERNAL");
            context.setVpnConnection(true);
            context.setAccessContext("세션_하이재킹");

            double riskScore = calculateContextRiskScore(context);
            context.setBehaviorAnomalyScore(riskScore / 100.0);
            context.addAnomalyIndicator("ip_change_in_session");
            context.addAnomalyIndicator("location_change");
            context.addAnomalyIndicator("vpn_detected");
            context.addAnomalyIndicator("suspicious_activity");
            context.setRiskCategory("CRITICAL");

            context.addMetadata("documentType", "behavior");
            context.addMetadata("eventId", UUID.randomUUID().toString());
            context.addMetadata("timestamp", hijackTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("accessTime", hijackTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            context.addMetadata("attackType", "session_hijacking");
            context.addMetadata("originalIP", originalIP);
            context.addMetadata("hijackedIP", hijackedIP);
            context.addMetadata("sessionPhase", "hijacked");
            context.addMetadata("patternType", "attack_session_hijacking");
            context.addMetadata("riskLevel", "critical");
            // Layer3 ThreatIntelligence용
            context.addMetadata("threatActor", "Session-Hijacker-APT");
            context.addMetadata("campaignId", "CAMPAIGN-SH-001");
            context.addMetadata("campaignName", "Session Hijacking Campaign 2024");
            context.addMetadata("iocIndicator", hijackedIP + ",vpn_detected,ip_change");
            // Layer3 HistoricalContext용
            context.addMetadata("incidentId", "INC-SH-" + UUID.randomUUID().toString().substring(0, 8));
            context.addMetadata("mitreTactic", "TA0001-InitialAccess");
            // Layer3 SystemContext용
            context.addMetadata("assetCriticality", "CRITICAL");

            behaviorVectorService.storeBehavior(context);
            patterns++;
        }

        return patterns;
    }

    /**
     * Impossible Travel 공격 패턴 생성
     * 물리적으로 불가능한 이동 감지
     */
    private int generateImpossibleTravelPatterns(Random random) {
        int patterns = 0;

        log.info("  Impossible Travel 공격 패턴 생성...");

        String koreaIP = simulationConfig.getAttackIps().getImpossibleTravel().getKorea();
        String usaIP = simulationConfig.getAttackIps().getImpossibleTravel().getUsa();
        String userId = "finance_manager";

        LocalDateTime koreaLoginTime = LocalDateTime.now().minusDays(1).withHour(9);

        // 1. 서울에서 로그인
        BehavioralAnalysisContext koreaContext = new BehavioralAnalysisContext();
        koreaContext.setUserId(userId);
        koreaContext.setOrganizationId("contexa");
        koreaContext.setCurrentActivity("로그인");
        koreaContext.setRemoteIp(koreaIP);

        koreaContext.setUserAgent("Windows 10, Chrome 120.0");
        koreaContext.setBrowserInfo("Chrome 120.0");
        koreaContext.setOsInfo("Windows 10");
        koreaContext.setNewDevice(false);
        koreaContext.setNewLocation(false);

        koreaContext.setLastActivityTime(koreaLoginTime);
        koreaContext.setActivityVelocity(2.0);

        koreaContext.generateSessionFingerprint();
        koreaContext.generateDeviceFingerprint();

        koreaContext.setGeoLocation(simulationConfig.getLocations().get(koreaIP));
        koreaContext.setNetworkSegment("INTERNAL");
        koreaContext.setVpnConnection(false);
        koreaContext.setAccessContext("정상_로그인_서울");

        koreaContext.setBehaviorAnomalyScore(0.1);
        koreaContext.setRiskCategory("LOW");

        koreaContext.addMetadata("documentType", "behavior");
        koreaContext.addMetadata("eventId", UUID.randomUUID().toString());
        koreaContext.addMetadata("timestamp", koreaLoginTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        koreaContext.addMetadata("accessTime", koreaLoginTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        koreaContext.addMetadata("location", "Seoul, Korea");
        koreaContext.addMetadata("patternType", "travel_start");
        koreaContext.addMetadata("riskLevel", "low");
        // Layer3 ThreatIntelligence용 - 정상 로그인
        koreaContext.addMetadata("threatActor", "NONE");
        koreaContext.addMetadata("campaignId", "NONE");
        koreaContext.addMetadata("campaignName", "");
        koreaContext.addMetadata("iocIndicator", "");
        // Layer3 HistoricalContext용
        koreaContext.addMetadata("incidentId", "");
        koreaContext.addMetadata("mitreTactic", "");
        // Layer3 SystemContext용
        koreaContext.addMetadata("assetCriticality", "LOW");

        behaviorVectorService.storeBehavior(koreaContext);
        patterns++;

        // 2. 5분 후 뉴욕에서 로그인 (물리적 불가능)
        LocalDateTime usaLoginTime = koreaLoginTime.plusMinutes(5);

        BehavioralAnalysisContext usaContext = new BehavioralAnalysisContext();
        usaContext.setUserId(userId);
        usaContext.setOrganizationId("contexa");
        usaContext.setCurrentActivity("ProtectableDataService.getAllCustomerData");
        usaContext.setRemoteIp(usaIP);

        usaContext.setUserAgent("Windows 10, Chrome 120.0");
        usaContext.setBrowserInfo("Chrome 120.0");
        usaContext.setOsInfo("Windows 10");
        usaContext.setNewDevice(false);
        usaContext.setNewLocation(true); // 위치 변경

        usaContext.setLastActivityTime(usaLoginTime);
        usaContext.setActivityVelocity(30.0);

        usaContext.generateSessionFingerprint();
        usaContext.generateDeviceFingerprint();

        usaContext.setGeoLocation(simulationConfig.getLocations().get(usaIP));
        usaContext.setNetworkSegment("EXTERNAL");
        usaContext.setVpnConnection(false);
        usaContext.setAccessContext("불가능한_이동");

        double riskScore = simulationConfig.getRiskScores().getImpossibleTravel() * 100;
        usaContext.setBehaviorAnomalyScore(riskScore / 100.0);
        usaContext.addAnomalyIndicator("impossible_travel");
        usaContext.addAnomalyIndicator("rapid_location_change");
        usaContext.addAnomalyIndicator("suspicious_access");
        usaContext.setRiskCategory("CRITICAL");

        int distance = simulationConfig.getDistances().get("Seoul-NewYork");
        usaContext.addMetadata("documentType", "behavior");
        usaContext.addMetadata("eventId", UUID.randomUUID().toString());
        usaContext.addMetadata("timestamp", usaLoginTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        usaContext.addMetadata("accessTime", usaLoginTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        usaContext.addMetadata("attackType", "impossible_travel");
        usaContext.addMetadata("previousLocation", "Seoul, Korea");
        usaContext.addMetadata("currentLocation", "New York, USA");
        usaContext.addMetadata("distance", distance + " km");
        usaContext.addMetadata("timeGap", "5 minutes");
        usaContext.addMetadata("physicallyPossible", "false");
        usaContext.addMetadata("patternType", "attack_impossible_travel");
        usaContext.addMetadata("riskLevel", "critical");
        // Layer3 ThreatIntelligence용
        usaContext.addMetadata("threatActor", "Account-Takeover-Group");
        usaContext.addMetadata("campaignId", "CAMPAIGN-IT-001");
        usaContext.addMetadata("campaignName", "Impossible Travel Attack 2024");
        usaContext.addMetadata("iocIndicator", usaIP + ",rapid_location_change,impossible_travel");
        // Layer3 HistoricalContext용
        usaContext.addMetadata("incidentId", "INC-IT-" + UUID.randomUUID().toString().substring(0, 8));
        usaContext.addMetadata("mitreTactic", "TA0001-InitialAccess");
        // Layer3 SystemContext용
        usaContext.addMetadata("assetCriticality", "CRITICAL");

        behaviorVectorService.storeBehavior(usaContext);
        patterns++;

        return patterns;
    }

    /**
     * 접근 시간 생성 (시간대 범위 기반)
     */
    private LocalDateTime generateAccessTime(LocalDateTime baseDate, String timeRange, Random random) {
        if (timeRange == null || timeRange.isEmpty()) {
            // 시간대 제한이 없으면 랜덤
            return baseDate.withHour(random.nextInt(24)).withMinute(random.nextInt(60));
        }

        String[] parts = timeRange.split("-");
        if (parts.length != 2) {
            return baseDate.withHour(10);  // 기본값
        }

        try {
            int startHour = Integer.parseInt(parts[0].split(":")[0]);
            int endHour = Integer.parseInt(parts[1].split(":")[0]);

            int hour = startHour + random.nextInt(endHour - startHour + 1);
            return baseDate.withHour(hour).withMinute(random.nextInt(60));
        } catch (Exception e) {
            return baseDate.withHour(10);  // 파싱 실패 시 기본값
        }
    }

    /**
     * 사용자별 적절한 활동 선택
     */
    private String selectActivityForUser(String userId, Random random) {
        List<String> activities = NORMAL_ACTIVITIES;

        switch (userId) {
            case "admin":
                // 관리자는 일반 활동 + 관리 활동
                if (random.nextDouble() < 0.3) {
                    activities = ADMIN_ACTIVITIES;
                }
                break;
            case "dev_lead":
            case "dev_user":
                // 개발자는 일반 활동 + 개발 활동
                if (random.nextDouble() < 0.4) {
                    activities = DEV_ACTIVITIES;
                }
                break;
            case "finance_manager":
                // 재무 관리자는 일반 활동 + 재무 활동
                if (random.nextDouble() < 0.3) {
                    activities = FINANCE_ACTIVITIES;
                }
                break;
            default:
                // 기본은 일반 활동만
                break;
        }

        return activities.get(random.nextInt(activities.size()));
    }

    /**
     * 정상적인 내부 IP 주소 생성
     */
    private String generateNormalIpAddress(String userId) {
        // 사용자별 고정 IP 대역 할당 (일관성 유지)
        switch (userId) {
            case "admin":
                return "192.168.1.100";
            case "dev_lead":
                return "192.168.1.101";
            case "dev_user":
                return "192.168.1.102";
            case "op_user":
                return "192.168.1.103";
            case "finance_manager":
                return "192.168.1.104";
            default:
                return "192.168.1.199";
        }
    }

    /**
     * 초기 컨텍스트 생성
     */
    private BehavioralAnalysisContext createInitialContext(String userId) {
        BehavioralAnalysisContext context = new BehavioralAnalysisContext();
        context.setUserId(userId);
        context.setOrganizationId("contexa");
        context.setRemoteIp(generateNormalIpAddress(userId));
        context.setCurrentActivity("로그인");
        context.addActivityToSequence("로그인");
        return context;
    }

    /**
     * 디바이스 정보 생성
     */
    private String generateDeviceInfo(String userId, Random random) {
        String[] browsers = {"Chrome 120.0", "Edge 119.0", "Firefox 121.0"};
        String[] os = {"Windows 10", "Windows 11", "macOS 14.0"};

        // 사용자별로 일관된 디바이스 사용 (가끔 변경)
        int browserIdx = userId.hashCode() % browsers.length;
        int osIdx = userId.hashCode() % os.length;

        // 5% 확률로 다른 디바이스 사용
        if (random.nextDouble() < 0.05) {
            browserIdx = random.nextInt(browsers.length);
            osIdx = random.nextInt(os.length);
        }

        return os[osIdx] + ", " + browsers[browserIdx];
    }

    // ============================================
    // REDIS BASELINE VECTOR INITIALIZATION
    // ============================================

    /**
     * Redis BaselineVector 초기화
     * 모든 사용자의 30일간 정상 활동을 기반으로 BaselineVector 생성 및 Redis 저장
     */
    private void initializeBaselineVectors() {
        log.info("\n[Redis 초기화] BaselineVector 생성 시작...");

        Random random = new Random();

        for (String userId : USERS) {
            try {
                log.info("  사용자 {} BaselineVector 생성 중...", userId);

                // 1. 30일간의 정상 활동 집계
                List<HCADContext> normalActivities = generateAggregatedNormalActivities(userId, 30, random);

                if (normalActivities.isEmpty()) {
                    log.warn("  사용자 {} 정상 활동 데이터 없음, 스킵", userId);
                    continue;
                }

                // 2. BaselineVector 생성
                BaselineVector baseline = new BaselineVector();
                baseline.setUserId(userId);
                baseline.setUpdateCount((long) normalActivities.size()); // int → Long
                baseline.setConfidence(calculateInitialConfidence(normalActivities.size()));
                baseline.setLastUpdated(LocalDateTime.now().toInstant(java.time.ZoneOffset.UTC)); // LocalDateTime → Instant

                // 3. 평균 벡터 계산
                double[] avgVector = calculateAverageVector(normalActivities);
                baseline.setVector(avgVector);

                // 4. 통계 정보 설정
                baseline.setMeanRequestInterval(calculateMeanInterval(normalActivities));
                baseline.setAvgRequestCount((long) (normalActivities.size() / 30.0)); // double → Long
                baseline.setAvgTrustScore(0.8); // 정상 사용자 기본 신뢰도

                // 5. Redis 저장
                saveBaselineToRedis(userId, baseline);

                log.info("  ✅ {} BaselineVector 저장 완료: confidence={}, updateCount={}, avgVectorNorm={}",
                    userId,
                    String.format("%.3f", baseline.getConfidence()),
                    baseline.getUpdateCount(),
                    String.format("%.3f", calculateVectorNorm(avgVector)));

            } catch (Exception e) {
                log.error("  ❌ {} BaselineVector 생성 실패: {}", userId, e.getMessage(), e);
            }
        }
    }

    /**
     * 30일간의 정상 활동 집계하여 HCADContext 리스트 생성
     */
    private List<HCADContext> generateAggregatedNormalActivities(String userId, int days, Random random) {
        List<HCADContext> activities = new ArrayList<>();

        try {
            for (int day = 0; day < days; day++) {
                LocalDateTime baseTime = LocalDateTime.now().minusDays(days - day);

                // 업무 시간 (9시-18시) 동안의 활동
                for (int hour = 9; hour <= 17; hour++) {
                    // 시간당 2-5개의 활동
                    int activitiesPerHour = 2 + random.nextInt(4);

                    for (int activity = 0; activity < activitiesPerHour; activity++) {
                        LocalDateTime activityTime = baseTime
                            .withHour(hour)
                            .withMinute(random.nextInt(60))
                            .withSecond(random.nextInt(60));

                        // HCADContext 직접 생성 (Mock 대신)
                        HCADContext hcadContext = new HCADContext();
                        hcadContext.setUserId(userId);
                        hcadContext.setSessionId(UUID.randomUUID().toString());
                        hcadContext.setRequestPath("/api/" + selectActivityForUser(userId, random).replace(" ", "_"));
                        hcadContext.setHttpMethod("GET");
                        hcadContext.setRemoteIp(generateNormalIpAddress(userId));
                        hcadContext.setTimestamp(activityTime.toInstant(java.time.ZoneOffset.UTC)); // LocalDateTime → Instant
                        hcadContext.setUserAgent(generateDeviceInfo(userId, random));
                        hcadContext.setIsNewSession(random.nextDouble() < 0.05); // 5% 새 세션
                        hcadContext.setDeviceId(userId + "-device-" + (userId.hashCode() % 3)); // 사용자당 1-3개 디바이스

                        activities.add(hcadContext);
                    }
                }
            }
        } catch (Exception e) {
            log.error("[InitVectorStore] HCADContext 생성 실패: userId={}", userId, e);
        }

        return activities;
    }

    /**
     * HCADContext 리스트로부터 평균 벡터 계산
     */
    private double[] calculateAverageVector(List<HCADContext> activities) {
        if (activities.isEmpty()) {
            return new double[384];
        }

        double[] sumVector = new double[384];
        int count = 0;

        for (HCADContext context : activities) {
            try {
                double[] vector = context.toVector();
                if (vector != null && vector.length == 384) {
                    for (int i = 0; i < 384; i++) {
                        sumVector[i] += vector[i];
                    }
                    count++;
                }
            } catch (Exception e) {
                log.debug("벡터 변환 실패, 스킵: {}", e.getMessage());
            }
        }

        if (count == 0) {
            return new double[384];
        }

        // 평균 계산
        for (int i = 0; i < 384; i++) {
            sumVector[i] /= count;
        }

        return sumVector;
    }

    /**
     * 초기 Confidence 계산 (활동 횟수 기반)
     */
    private double calculateInitialConfidence(int activityCount) {
        // 100회 이하: 0.5
        // 500회: 0.8
        // 1000회 이상: 0.9
        if (activityCount < 100) {
            return 0.5;
        } else if (activityCount < 500) {
            return 0.5 + (activityCount - 100) * 0.3 / 400.0; // 0.5 → 0.8
        } else if (activityCount < 1000) {
            return 0.8 + (activityCount - 500) * 0.1 / 500.0; // 0.8 → 0.9
        } else {
            return 0.9;
        }
    }

    /**
     * 평균 요청 간격 계산
     */
    private double calculateMeanInterval(List<HCADContext> activities) {
        if (activities.size() < 2) {
            return 300.0; // 기본값 5분
        }

        // 시간순 정렬
        activities.sort(Comparator.comparing(HCADContext::getTimestamp));

        long totalInterval = 0;
        int count = 0;

        for (int i = 1; i < activities.size(); i++) {
            java.time.Instant prev = activities.get(i - 1).getTimestamp(); // Instant 타입
            java.time.Instant curr = activities.get(i).getTimestamp(); // Instant 타입
            if (prev != null && curr != null) {
                long interval = Duration.between(prev, curr).getSeconds();
                if (interval > 0 && interval < 3600) { // 1시간 이하만 카운트
                    totalInterval += interval;
                    count++;
                }
            }
        }

        if (count == 0) {
            return 300.0;
        }

        return (double) totalInterval / count;
    }

    /**
     * 벡터 노름(길이) 계산
     */
    private double calculateVectorNorm(double[] vector) {
        double sum = 0.0;
        for (double v : vector) {
            sum += v * v;
        }
        return Math.sqrt(sum);
    }

    /**
     * BaselineVector를 Redis에 저장
     */
    private void saveBaselineToRedis(String userId, BaselineVector baseline) {
        try {
            String key = HCADRedisKeys.baselineVector(userId);
            redisTemplate.opsForValue().set(key, baseline, Duration.ofDays(baselineTtlDays));

            if (log.isDebugEnabled()) {
                log.debug("[InitVectorStore] Baseline saved to Redis: key={}, confidence={}, updateCount={}",
                    key,
                    String.format("%.3f", baseline.getConfidence()),
                    baseline.getUpdateCount());
            }
        } catch (Exception e) {
            log.error("[InitVectorStore] Redis 저장 실패: userId={}, error={}", userId, e.getMessage(), e);
            throw new RuntimeException("Baseline Vector Redis 저장 실패", e);
        }
    }

    /**
     * Redis 초기화 검증
     */
    private void verifyRedisInitialization() {
        log.info("\n========================================");
        log.info("Redis 초기화 검증 중...");
        log.info("========================================");

        int successCount = 0;
        int totalUsers = USERS.size();

        for (String userId : USERS) {
            try {
                String key = HCADRedisKeys.baselineVector(userId);
                Object value = redisTemplate.opsForValue().get(key);

                if (value instanceof BaselineVector) {
                    BaselineVector baseline = (BaselineVector) value;
                    log.info("✅ {}: confidence={}, updateCount={}, vectorNorm={}",
                        userId,
                        String.format("%.3f", baseline.getConfidence()),
                        baseline.getUpdateCount(),
                        String.format("%.3f", calculateVectorNorm(baseline.getVector())));
                    successCount++;
                } else {
                    log.error("❌ {}: BaselineVector 없음 (type={})", userId,
                        value != null ? value.getClass().getSimpleName() : "null");
                }
            } catch (Exception e) {
                log.error("❌ {}: 검증 실패 - {}", userId, e.getMessage());
            }
        }

        log.info("\n========================================");
        log.info("검증 결과: {}/{}개 사용자 BaselineVector 저장 완료", successCount, totalUsers);

        if (successCount == totalUsers) {
            log.info("✅ ✅ ✅ 모든 사용자 BaselineVector가 성공적으로 Redis에 저장되었습니다!");
        } else {
            log.warn("⚠️  일부 사용자의 BaselineVector 저장 실패");
        }

        log.info("========================================\n");
    }

    public static void main(String[] args) {
        SpringApplication.run(InitializeVectorStore.class, args);
    }
}