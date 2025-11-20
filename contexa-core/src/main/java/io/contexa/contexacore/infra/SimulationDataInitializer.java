package io.contexa.contexacore.infra;

import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.domain.entity.SecurityAction;
import io.contexa.contexacore.domain.entity.SoarApprovalRequest;
import io.contexa.contexacore.domain.entity.ApprovalNotification;
import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import io.contexa.contexacore.repository.ThreatIndicatorRepository;
import io.contexa.contexacore.repository.SecurityActionRepository;
import io.contexa.contexacore.repository.SoarApprovalRequestRepository;
import io.contexa.contexacore.repository.ApprovalNotificationRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

/**
 * contexa 시뮬레이션 데이터 초기화 서비스
 * 
 * 시스템 시작 시 필요한 보안 시뮬레이션 데이터를 생성하고
 * 데이터베이스와 Kafka에 초기 데이터를 삽입합니다.
 * 
 * 기존 엔티티와 Spring Data JPA 표준 API를 사용합니다.
 */
@Slf4j
//@Component
public class SimulationDataInitializer implements CommandLineRunner {

    // JPA Repository - Spring Data 표준 API 사용
    private final SecurityIncidentRepository securityIncidentRepository;
    private final ThreatIndicatorRepository threatIndicatorRepository;
    private final SecurityActionRepository securityActionRepository;
    private final SoarApprovalRequestRepository soarApprovalRequestRepository;
    private final ApprovalNotificationRepository approvalNotificationRepository;

    // Kafka Producer - Spring Kafka 표준 API 사용 (Optional)
    private final KafkaTemplate<String, Object> kafkaTemplate;

    // 생성자 - KafkaTemplate을 Optional로 처리
    public SimulationDataInitializer(
            SecurityIncidentRepository securityIncidentRepository,
            ThreatIndicatorRepository threatIndicatorRepository,
            SecurityActionRepository securityActionRepository,
            SoarApprovalRequestRepository soarApprovalRequestRepository,
            ApprovalNotificationRepository approvalNotificationRepository,
            @Autowired(required = false) KafkaTemplate<String, Object> kafkaTemplate) {
        this.securityIncidentRepository = securityIncidentRepository;
        this.threatIndicatorRepository = threatIndicatorRepository;
        this.securityActionRepository = securityActionRepository;
        this.soarApprovalRequestRepository = soarApprovalRequestRepository;
        this.approvalNotificationRepository = approvalNotificationRepository;
        this.kafkaTemplate = kafkaTemplate;
    }
    
    @Value("${contexa.simulation.data.enabled:true}")
    private boolean simulationDataEnabled;
    
    @Value("${contexa.simulation.data.clear-existing:false}")
    private boolean clearExistingData;
    
    private final Random random = new Random();
    
    @Override
    @Transactional
    public void run(String... args) throws Exception {
        if (!simulationDataEnabled) {
            log.info("시뮬레이션 데이터 생성이 비활성화되어 있습니다.");
            return;
        }
        
        // 데이터가 이미 존재하는지 확인
        if (isDataAlreadyInitialized()) {
            log.info("시뮬레이션 데이터가 이미 존재합니다. 초기화를 건너뜁니다.");
            return;
        }
        
        log.info("contexa 시뮬레이션 데이터 초기화 시작");
        
        try {
            // 1. 기존 데이터 정리 (옵션)
            if (clearExistingData) {
                clearExistingSimulationData();
            }
            
            // 2. 기본 위협 지표 생성
            List<ThreatIndicator> indicators = createThreatIndicators();
            log.info("{} 개의 위협 지표 생성 완료", indicators.size());
            
            // 3. 보안 인시던트 생성
            List<SecurityIncident> incidents = createSecurityIncidents(indicators);
            log.info("{} 개의 보안 인시던트 생성 완료", incidents.size());
            
            // 4. 보안 액션 생성
            List<SecurityAction> actions = createSecurityActions(incidents);
            log.info("{} 개의 보안 액션 생성 완료", actions.size());
            
            // 5. SOAR 승인 요청 생성
            List<SoarApprovalRequest> approvals = createSoarApprovalRequests();
            log.info("{} 개의 SOAR 승인 요청 생성 완료", approvals.size());

            // 6. 승인 알림 생성
            List<ApprovalNotification> notifications = createApprovalNotifications(approvals);
            log.info("{} 개의 승인 알림 생성 완료", notifications.size());
            
            // 8. Kafka 토픽에 샘플 이벤트 발송
            sendSampleKafkaEvents(incidents, indicators);
            log.info("Kafka 토픽에 샘플 이벤트 발송 완료");
            
            log.info("🎉 contexa 시뮬레이션 데이터 초기화 완료!");
            
        } catch (Exception e) {
            log.error(" 시뮬레이션 데이터 초기화 중 오류 발생", e);
            throw e;
        }
    }
    
    /**
     * 시뮬레이션 데이터가 이미 초기화되었는지 확인
     * 특정 ID를 가진 데이터가 존재하는지 체크하여 중복 생성 방지
     */
    private boolean isDataAlreadyInitialized() {
        // 특정 ID로 생성되는 인시던트가 이미 존재하는지 확인
        boolean incidentExists = securityIncidentRepository.existsById("INC-2025-001");
        if (incidentExists) {
            log.info("기존 시뮬레이션 데이터 감지됨 - SecurityIncident: INC-2025-001");
            // 추가로 다른 데이터 상태도 체크
            long incidentCount = securityIncidentRepository.count();
            long indicatorCount = threatIndicatorRepository.count();
            long actionCount = securityActionRepository.count();
            log.info("현재 데이터 상태 - 인시던트: {}, 위협지표: {}, 보안액션: {}", 
                    incidentCount, indicatorCount, actionCount);
            return true;
        }
        return false;
    }
    
    /**
     * 기존 시뮬레이션 데이터 정리
     */
    private void clearExistingSimulationData() {
        log.info("🧹 기존 시뮬레이션 데이터 정리 중...");
        
        // 연관 엔티티부터 삭제 (외래키 제약 조건)
        approvalNotificationRepository.deleteAll();
        soarApprovalRequestRepository.deleteAll();
        securityActionRepository.deleteAll();
        securityIncidentRepository.deleteAll();
        threatIndicatorRepository.deleteAll();
        
        log.info("기존 데이터 정리 완료");
    }
    
    /**
     * 위협 지표 생성 (Layer 1/2/3 계층별)
     */
    private List<ThreatIndicator> createThreatIndicators() {
        log.info("계층별 위협 지표 생성 중...");
        
        List<ThreatIndicator> indicators = Arrays.asList(
            // =========================
            // Layer 1 위협 (빠른 필터링용)
            // =========================
            ThreatIndicator.builder()
                .type(ThreatIndicator.IndicatorType.IP_ADDRESS)
                .value("192.168.100.50")
                .severity(ThreatIndicator.Severity.HIGH)
                .confidence(0.8)
                .source("Internal Security System")
                .description("내부 네트워크에서 의심스러운 활동을 보이는 IP")
                .threatActor("APT-29")
                .malwareFamily("Cobalt Strike")
                .mitreAttackId("T1071.001")
                .mitreTactic("Command and Control")
                .mitreTechnique("Application Layer Protocol")
                .tags(Set.of("internal", "suspicious", "cobalt-strike", "layer1"))
                .detectedAt(LocalDateTime.now().minusDays(1))
                .build(),
                
            ThreatIndicator.builder()
                .type(ThreatIndicator.IndicatorType.IP_ADDRESS)
                .value("203.0.113.45")
                .severity(ThreatIndicator.Severity.CRITICAL)
                .confidence(0.95)
                .source("Threat Intelligence Feed")
                .description("알려진 C&C 서버 IP 주소")
                .threatActor("Lazarus Group")
                .campaign("Hidden Cobra")
                .mitreAttackId("T1090")
                .mitreTactic("Command and Control")
                .mitreTechnique("Proxy")
                .tags(Set.of("c2", "lazarus", "critical", "layer1"))
                .detectedAt(LocalDateTime.now().minusDays(2))
                .build(),
                
            // Layer 1: 빠른 탐지용 악성 도메인
            ThreatIndicator.builder()
                .type(ThreatIndicator.IndicatorType.DOMAIN)
                .value("malicious-update.com")
                .severity(ThreatIndicator.Severity.HIGH)
                .confidence(0.9)
                .source("DNS Security Provider")
                .description("피싱 공격에 사용되는 악성 도메인")
                .threatActor("Unknown")
                .mitreAttackId("T1566.002")
                .mitreTactic("Initial Access")
                .mitreTechnique("Spearphishing Link")
                .tags(Set.of("phishing", "domain", "fake-update", "layer1"))
                .detectedAt(LocalDateTime.now().minusHours(12))
                .build(),
                
            // =========================
            // Layer 2 위협 (컨텍스트 분석용)
            // =========================
            // 파일 해시 - 컨텍스트 분석 필요
            ThreatIndicator.builder()
                .type(ThreatIndicator.IndicatorType.FILE_HASH)
                .value("5d41402abc4b2a76b9719d911017c592")
                .severity(ThreatIndicator.Severity.CRITICAL)
                .confidence(0.98)
                .source("Malware Analysis Lab")
                .description("랜섬웨어 바이너리 MD5 해시")
                .malwareFamily("WannaCry")
                .mitreAttackId("T1486")
                .mitreTactic("Impact")
                .mitreTechnique("Data Encrypted for Impact")
                .tags(Set.of("ransomware", "wannacry", "hash", "layer2"))
                .detectedAt(LocalDateTime.now().minusHours(6))
                .build(),
                
            // Layer 2: 의심스러운 URL - 컨텍스트 분석용
            ThreatIndicator.builder()
                .type(ThreatIndicator.IndicatorType.URL)
                .value("http://suspicious-site.com/download/payload.exe")
                .severity(ThreatIndicator.Severity.HIGH)
                .confidence(0.85)
                .source("Web Security Gateway")
                .description("악성코드 다운로드 URL")
                .mitreAttackId("T1105")
                .mitreTactic("Command and Control")
                .mitreTechnique("Ingress Tool Transfer")
                .tags(Set.of("malware-download", "payload", "exe", "layer2"))
                .detectedAt(LocalDateTime.now().minusHours(3))
                .build(),
                
            // =========================
            // Layer 3 위협 (전문가 분석용)
            // =========================
            // 사용자 계정 침해 지표 - 전문가 분석 필요
            ThreatIndicator.builder()
                .type(ThreatIndicator.IndicatorType.USER_ACCOUNT)
                .value("admin@company.com")
                .severity(ThreatIndicator.Severity.MEDIUM)
                .confidence(0.7)
                .source("Identity Access Management")
                .description("비정상적인 로그인 패턴을 보이는 계정")
                .mitreAttackId("T1078.004")
                .mitreTactic("Defense Evasion")
                .mitreTechnique("Valid Accounts")
                .tags(Set.of("account-compromise", "admin", "abnormal-login", "layer3"))
                .detectedAt(LocalDateTime.now().minusMinutes(30))
                .build(),
                
            // Layer 3: 고도화된 APT 공격 탐지
            ThreatIndicator.builder()
                .type(ThreatIndicator.IndicatorType.DOMAIN)
                .value("APT-SOPHISTICATED-CAMPAIGN-2025")
                .severity(ThreatIndicator.Severity.CRITICAL)
                .confidence(0.95)
                .source("Advanced Threat Intelligence")
                .description("고도화된 APT 공격 캐페인 - 다단계 대상 공격")
                .threatActor("APT-41")
                .campaign("Operation Dragon Strike")
                .malwareFamily("Custom RAT")
                .mitreAttackId("TA0002")
                .mitreTactic("Execution")
                .mitreTechnique("Multi-Stage Attack")
                .tags(Set.of("apt", "sophisticated", "multi-stage", "layer3"))
                .detectedAt(LocalDateTime.now().minusMinutes(10))
                .build(),
                
            // Layer 3: 제로데이 익스플로잇
            ThreatIndicator.builder()
                .type(ThreatIndicator.IndicatorType.FILE_HASH)
                .value("CVE-2024-UNKNOWN-ZERO-DAY")
                .severity(ThreatIndicator.Severity.CRITICAL)
                .confidence(0.88)
                .source("Zero-Day Research Lab")
                .description("새로운 제로데이 취약점 익스플로잇 탐지")
                .mitreAttackId("T1190")
                .mitreTactic("Initial Access")
                .mitreTechnique("Exploit Public-Facing Application")
                .tags(Set.of("zero-day", "exploit", "critical", "layer3"))
                .detectedAt(LocalDateTime.now().minusMinutes(5))
                .build()
        );
        
        log.info("계층별 위협 지표 생성 완료 - Layer1: {}개, Layer2: {}개, Layer3: {}개",
                indicators.stream().filter(i -> i.getTags().contains("layer1")).count(),
                indicators.stream().filter(i -> i.getTags().contains("layer2")).count(), 
                indicators.stream().filter(i -> i.getTags().contains("layer3")).count());
        
        return threatIndicatorRepository.saveAll(indicators);
    }
    
    /**
     * 보안 인시던트 생성 (Layer 1/2/3 계층별)
     */
    private List<SecurityIncident> createSecurityIncidents(List<ThreatIndicator> indicators) {
        log.info("계층별 보안 인시던트 생성 중...");
        
        // =========================
        // Layer 1 인시던트 (초고속 필터링)
        // =========================
        // Layer 1: 단순 이상 패턴 탐지
        SecurityIncident incident1 = SecurityIncident.builder()
            .incidentId("INC-2025-001")
            .type(SecurityIncident.IncidentType.INTRUSION_ATTEMPT)
            .threatLevel(SecurityIncident.ThreatLevel.HIGH)
            .status(SecurityIncident.IncidentStatus.INVESTIGATING)
            .description("외부 IP에서 SSH 무차별 대입 공격 탐지")
            .sourceIp("203.0.113.45")
            .destinationIp("192.168.1.100")
            .affectedUser("server-admin")
            .organizationId("CONTEXASEC-001")
            .riskScore(0.85)
            .detectedBy("Intrusion Detection System")
            .detectionSource("Network Monitor")
            .detectedAt(LocalDateTime.now().minusHours(2))
            .autoResponseEnabled(true)
            .requiresApproval(true)
            .mitreAttackMapping("T1110.001")
            .eventCount(247)
            .lastEventTime(LocalDateTime.now().minusMinutes(15))
            .build();
        
        // 모든 컬렉션 필드 수동 초기화 (JPA @ElementCollection 및 @Builder.Default 이슈 해결)
        initializeSecurityIncidentCollections(incident1);
        
        // 기본값 설정 (Builder에서 null인 경우에만)
        if (incident1.getAutoResponseEnabled() == null) {
            incident1.setAutoResponseEnabled(true);
        }
        if (incident1.getRequiresApproval() == null) {
            incident1.setRequiresApproval(true);
        }
        if (incident1.getEventCount() == null) {
            incident1.setEventCount(247);
        }
        
        // 지표는 저장 후에 연결하지 않음 (ManyToMany 관계 문제 해결)
        incident1.addAffectedAsset("SSH-001");
        incident1.addAffectedAsset("SERVER-001");
        incident1.addTag("brute-force");
        incident1.addTag("ssh");
        incident1.addTag("external");
        incident1.addTag("layer1");  // Layer 1 태그 추가
        
        List<SecurityIncident> incidents = new ArrayList<>();
        incidents.add(incident1);
                
        // Layer 1: 자동 차단 가능한 악성코드 탐지
        SecurityIncident incident2 = SecurityIncident.builder()
            .incidentId("INC-2025-002")
            .type(SecurityIncident.IncidentType.MALWARE_DETECTION)
            .threatLevel(SecurityIncident.ThreatLevel.CRITICAL)
            .status(SecurityIncident.IncidentStatus.CONTAINED)
            .description("랜섬웨어 바이너리 실행 시도 탐지 및 격리")
            .sourceIp("192.168.100.50")
            .affectedUser("john.doe")
            .organizationId("CONTEXASEC-001")
            .riskScore(0.95)
            .detectedBy("Endpoint Detection Response")
            .detectionSource("EDR Agent")
            .detectedAt(LocalDateTime.now().minusHours(6))
            .autoResponseEnabled(true)
            .requiresApproval(false) // 자동 대응
            .mitreAttackMapping("T1486")
            .eventCount(1)
            .lastEventTime(LocalDateTime.now().minusHours(6))
            .build();
        
        // 모든 컬렉션 필드 수동 초기화 (JPA @ElementCollection 및 @Builder.Default 이슈 해결)
        initializeSecurityIncidentCollections(incident2);
        
        // 기본값 설정
        if (incident2.getAutoResponseEnabled() == null) {
            incident2.setAutoResponseEnabled(true);
        }
        if (incident2.getRequiresApproval() == null) {
            incident2.setRequiresApproval(false);
        }
        if (incident2.getEventCount() == null) {
            incident2.setEventCount(1);
        }
        
        // 지표는 저장 후에 연결하지 않음 (ManyToMany 관계 문제 해결)
        incident2.addAffectedAsset("WORKSTATION-050");
        incident2.addAffectedAsset("FILESERVER-001");
        incident2.addTag("ransomware");
        incident2.addTag("quarantine");
        incident2.addTag("edr");
        incident2.addTag("layer1");  // Layer 1 태그 추가
        incidents.add(incident2);
        
        // =========================
        // Layer 2 인시던트 (컨텍스트 분석)
        // =========================
        // Layer 2: 피싱 시도 - 컨텍스트 분석 필요
        SecurityIncident incident3 = SecurityIncident.builder()
            .incidentId("INC-2025-003")
            .type(SecurityIncident.IncidentType.PHISHING_ATTEMPT)
            .threatLevel(SecurityIncident.ThreatLevel.MEDIUM)
            .status(SecurityIncident.IncidentStatus.NEW)
            .description("직원에게 발송된 피싱 이메일 탐지")
            .affectedUser("jane.smith")
            .organizationId("CONTEXASEC-001")
            .riskScore(0.6)
            .detectedBy("Email Security Gateway")
            .detectionSource("Email Scanner")
            .detectedAt(LocalDateTime.now().minusHours(12))
            .autoResponseEnabled(true)
            .requiresApproval(false)
            .mitreAttackMapping("T1566.002")
            .eventCount(1)
            .lastEventTime(LocalDateTime.now().minusHours(12))
            .build();
        
        // 모든 컬렉션 필드 수동 초기화 (JPA @ElementCollection 및 @Builder.Default 이슈 해결)
        initializeSecurityIncidentCollections(incident3);
        
        // 기본값 설정
        if (incident3.getAutoResponseEnabled() == null) {
            incident3.setAutoResponseEnabled(true);
        }
        if (incident3.getRequiresApproval() == null) {
            incident3.setRequiresApproval(false);
        }
        if (incident3.getEventCount() == null) {
            incident3.setEventCount(1);
        }
        
        // 지표는 저장 후에 연결하지 않음 (ManyToMany 관계 문제 해결)
        incident3.addAffectedAsset("EMAIL-GATEWAY");
        incident3.addAffectedAsset("USER-EMAIL");
        incident3.addTag("phishing");
        incident3.addTag("email");
        incident3.addTag("blocked");
        incident3.addTag("layer2");  // Layer 2 태그 추가
        incidents.add(incident3);
        
        // 네 번째 인시던트: 권한 상승 시도
        SecurityIncident incident4 = SecurityIncident.builder()
            .incidentId("INC-2025-004")
            .type(SecurityIncident.IncidentType.PRIVILEGE_ESCALATION)
            .threatLevel(SecurityIncident.ThreatLevel.HIGH)
            .status(SecurityIncident.IncidentStatus.CONFIRMED)
            .description("일반 사용자 계정에서 관리자 권한 획득 시도")
            .affectedUser("admin@company.com")
            .organizationId("CONTEXASEC-001")
            .riskScore(0.75)
            .detectedBy("Active Directory Monitor")
            .detectionSource("Windows Event Logs")
            .detectedAt(LocalDateTime.now().minusMinutes(30))
            .autoResponseEnabled(true)
            .requiresApproval(true)
            .mitreAttackMapping("T1078.004")
            .eventCount(15)
            .lastEventTime(LocalDateTime.now().minusMinutes(5))
            .build();
        
        // 컬렉션 필드 수동 초기화
        initializeSecurityIncidentCollections(incident4);
        
        // 기본값 설정
        if (incident4.getAutoResponseEnabled() == null) {
            incident4.setAutoResponseEnabled(true);
        }
        if (incident4.getRequiresApproval() == null) {
            incident4.setRequiresApproval(true);
        }
        if (incident4.getEventCount() == null) {
            incident4.setEventCount(15);
        }
        
        // 지표는 저장 후에 연결하지 않음 (ManyToMany 관계 문제 해결)
        incident4.addAffectedAsset("DOMAIN-CONTROLLER");
        incident4.addAffectedAsset("ADMIN-WORKSTATION");
        incident4.addTag("privilege-escalation");
        incident4.addTag("admin");
        incident4.addTag("ad");
        incident4.addTag("layer2");  // Layer 2 태그 추가 - 컨텍스트 분석 필요
        incidents.add(incident4);
                
        // 다섯 번째 인시던트: 데이터 유출 시도
        SecurityIncident incident5 = SecurityIncident.builder()
            .incidentId("INC-2025-005")
            .type(SecurityIncident.IncidentType.DATA_EXFILTRATION)
            .threatLevel(SecurityIncident.ThreatLevel.CRITICAL)
            .status(SecurityIncident.IncidentStatus.INVESTIGATING)
            .description("대용량 데이터 외부 전송 시도 탐지")
            .sourceIp("192.168.100.50")
            .destinationIp("203.0.113.45")
            .affectedUser("database-admin")
            .organizationId("CONTEXASEC-001")
            .riskScore(0.9)
            .detectedBy("Data Loss Prevention")
            .detectionSource("DLP Agent")
            .detectedAt(LocalDateTime.now().minusHours(1))
            .autoResponseEnabled(true)
            .requiresApproval(true)
            .mitreAttackMapping("T1041")
            .eventCount(3)
            .lastEventTime(LocalDateTime.now().minusMinutes(20))
            .build();
        
        // 모든 컬렉션 필드 수동 초기화 (JPA @ElementCollection 및 @Builder.Default 이슈 해결)
        initializeSecurityIncidentCollections(incident5);
        
        // 기본값 설정
        if (incident5.getAutoResponseEnabled() == null) {
            incident5.setAutoResponseEnabled(true);
        }
        if (incident5.getRequiresApproval() == null) {
            incident5.setRequiresApproval(true);
        }
        if (incident5.getEventCount() == null) {
            incident5.setEventCount(3);
        }
        
        // 관련 지표 추가 (내부IP + C&C)
        // 지표는 저장 후에 연결하지 않음 (ManyToMany 관계 문제 해결)
        incident5.addAffectedAsset("DATABASE-001");
        incident5.addAffectedAsset("BACKUP-SERVER");
        incident5.addTag("data-exfiltration");
        incident5.addTag("database");
        incident5.addTag("critical");
        incident5.addTag("layer3");  // Layer 3 태그 추가 - 전문가 분석 필요
        incidents.add(incident5);
        
        return securityIncidentRepository.saveAll(incidents);
    }
    
    /**
     * SecurityIncident 컬렉션 필드 초기화 유틸리티 메서드
     * @Builder.Default로 인한 불변 컬렉션 문제 해결
     */
    private void initializeSecurityIncidentCollections(SecurityIncident incident) {
        if (incident.getIndicators() == null) {
            incident.setIndicators(new ArrayList<>());
        }
        if (incident.getActions() == null) {
            incident.setActions(new ArrayList<>());
        }
        if (incident.getAffectedAssets() == null) {
            incident.setAffectedAssets(new HashSet<>());
        }
        if (incident.getTags() == null) {
            incident.setTags(new HashSet<>());
        }
        if (incident.getRelatedEventIds() == null) {
            incident.setRelatedEventIds(new ArrayList<>());
        }
    }
    
    /**
     * 보안 액션 생성
     */
    private List<SecurityAction> createSecurityActions(List<SecurityIncident> incidents) {
        log.info("보안 액션 생성 중...");
        
        List<SecurityAction> actions = new ArrayList<>();
        
        for (SecurityIncident incident : incidents) {
            // 각 인시던트당 1-3개의 액션 생성
            actions.addAll(createActionsForIncident(incident));
        }
        
        return securityActionRepository.saveAll(actions);
    }
    
    /**
     * 특정 인시던트에 대한 액션들 생성
     */
    private List<SecurityAction> createActionsForIncident(SecurityIncident incident) {
        List<SecurityAction> actions = new ArrayList<>();
        
        // 기본 차단 액션
        SecurityAction blockAction = SecurityAction.builder()
            .incident(incident)
            .actionType("BLOCK_IP")
            .description(String.format("의심스러운 IP %s 차단", incident.getSourceIp()))
            .status(SecurityAction.ActionStatus.COMPLETED)
            .priority(1) // HIGH priority
            .completedAt(LocalDateTime.now().minusMinutes(random.nextInt(60)))
            .result("SUCCESS")
            .parameters(Map.of(
                "blocked_ip", incident.getSourceIp() != null ? incident.getSourceIp() : "Unknown",
                "block_duration", "24h",
                "firewall_rule", "DENY_ALL"
            ))
            .build();
        actions.add(blockAction);
        
        // 고위험 인시던트인 경우 격리 액션 추가
        if (incident.getThreatLevel().isHighRisk()) {
            SecurityAction isolateAction = SecurityAction.builder()
                .incident(incident)
                .actionType("ISOLATE_HOST")
                .description("영향받은 시스템을 네트워크에서 격리")
                .status(SecurityAction.ActionStatus.PENDING)
                .riskLevel(SoarTool.RiskLevel.CRITICAL)
                .requiresApproval(true)
                .priority(1)
                .build();
            isolateAction.addParameter("isolation_type", "NETWORK");
            isolateAction.addParameter("affected_hosts", String.join(",", incident.getAffectedAssets()));
            isolateAction.addParameter("isolation_duration", "UNTIL_INVESTIGATION_COMPLETE");
            actions.add(isolateAction);
        }
        
        // 알림 액션
        SecurityAction notifyAction = SecurityAction.builder()
            .incident(incident)
            .actionType("SEND_ALERT")
            .description("보안팀에 인시던트 발생 알림")
            .status(SecurityAction.ActionStatus.COMPLETED)
            .riskLevel(SoarTool.RiskLevel.LOW)
            .requiresApproval(false)
            .autoExecute(true)
            .priority(3)
            .completedAt(LocalDateTime.now().minusMinutes(random.nextInt(120)))
            .result("SUCCESS")
            .build();
        notifyAction.addParameter("notification_channels", "EMAIL,SLACK,SMS");
        notifyAction.addParameter("recipients", "security-team@company.com");
        notifyAction.addParameter("escalation_level", incident.getThreatLevel().name());
        actions.add(notifyAction);
        
        return actions;
    }
    
    /**
     * SOAR 승인 요청 생성
     */
    private List<SoarApprovalRequest> createSoarApprovalRequests() {
        log.info("SOAR 승인 요청 생성 중...");
        
        // 첫 번째 승인 요청
        SoarApprovalRequest approval1 = new SoarApprovalRequest();
        approval1.setRequestId("APR-2025-001");
        approval1.setPlaybookInstanceId("PB-INC-2025-001");
        approval1.setIncidentId("INC-2025-001");
        approval1.setSessionId("SESSION-001");
        approval1.setToolName("block_ip_advanced");
        approval1.setActionName("고급 IP 차단");
        approval1.setDescription("의심스러운 IP를 전사적으로 차단하고 관련 연결 추적");
        approval1.setParameters(Map.of(
            "ip_address", "203.0.113.45",
            "block_scope", "GLOBAL",
            "track_connections", true,
            "alert_on_retry", true
        ));
        approval1.setStatus("PENDING");
        approval1.setRiskLevel("HIGH");
        approval1.setRequestedBy("system");
        approval1.setOrganizationId("CONTEXASEC-001");
        approval1.setRequiredApprovers(2);
        approval1.setRequiredRoles(Arrays.asList("SECURITY_MANAGER", "SOC_LEAD"));
        
        // 두 번째 승인 요청
        SoarApprovalRequest approval2 = new SoarApprovalRequest();
        approval2.setRequestId("APR-2025-002");
        approval2.setPlaybookInstanceId("PB-INC-2025-004");
        approval2.setIncidentId("INC-2025-004");
        approval2.setSessionId("SESSION-002");
        approval2.setToolName("reset_user_credentials");
        approval2.setActionName("사용자 인증 정보 초기화");
        approval2.setDescription("침해된 계정의 인증 정보를 강제로 초기화");
        approval2.setParameters(Map.of(
            "user_account", "admin@company.com",
            "force_logout", true,
            "disable_account", true,
            "require_mfa_reset", true
        ));
        approval2.setStatus("APPROVED");
        approval2.setRiskLevel("HIGH");
        approval2.setRequestedBy("system");
        approval2.setOrganizationId("CONTEXASEC-001");
        approval2.setReviewerId("security-manager");
        approval2.setReviewerComment("계정 침해 확인, 즉시 초기화 필요");
        approval2.setApprovedAt(LocalDateTime.now().minusMinutes(15));
        approval2.setRequiredApprovers(1);
        approval2.setRequiredRoles(Arrays.asList("SECURITY_MANAGER"));
                
        // 세 번째 승인 요청
        SoarApprovalRequest approval3 = new SoarApprovalRequest();
        approval3.setRequestId("APR-2025-003");
        approval3.setPlaybookInstanceId("PB-INC-2025-005");
        approval3.setIncidentId("INC-2025-005");
        approval3.setSessionId("SESSION-003");
        approval3.setToolName("emergency_data_isolation");
        approval3.setActionName("긴급 데이터 격리");
        approval3.setDescription("데이터 유출 방지를 위한 긴급 데이터베이스 격리");
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("database_instances", Arrays.asList("DB-001", "BACKUP-001"));
        parameters.put("isolation_level", "COMPLETE");
        parameters.put("backup_before_isolation", true);
        parameters.put("notify_stakeholders", true);
        approval3.setParameters(parameters);
        approval3.setStatus("REJECTED");
        approval3.setRiskLevel("CRITICAL");
        approval3.setRequestedBy("system");
        approval3.setOrganizationId("CONTEXASEC-001");
        approval3.setReviewerId("ciso");
        approval3.setReviewerComment("데이터 격리보다는 네트워크 차단으로 대응");
        approval3.setApprovedAt(LocalDateTime.now().minusMinutes(30));
        approval3.setRequiredApprovers(2);
        approval3.setRequiredRoles(Arrays.asList("CISO", "DATA_OWNER"));
        
        List<SoarApprovalRequest> approvals = Arrays.asList(approval1, approval2, approval3);
        return soarApprovalRequestRepository.saveAll(approvals);
    }
    
    /**
     * 승인 알림 생성
     */
    private List<ApprovalNotification> createApprovalNotifications(List<SoarApprovalRequest> approvals) {
        log.info("승인 알림 생성 중...");
        
        List<ApprovalNotification> notifications = new ArrayList<>();
        
        for (SoarApprovalRequest approval : approvals) {
            ApprovalNotification notification = ApprovalNotification.builder()
                .requestId(approval.getRequestId())
                .notificationType("APPROVAL_REQUEST")
                .title(String.format("SOAR 도구 실행 승인 요청: %s", approval.getActionName()))
                .message(String.format(
                    "인시던트 %s에 대한 %s 도구 실행 승인이 필요합니다.\n" +
                    "위험도: %s\n" +
                    "설명: %s",
                    approval.getIncidentId(),
                    approval.getToolName(),
                    approval.getRiskLevel(),
                    approval.getDescription()
                ))
                .userId("security-manager")
                .targetRole("SECURITY_MANAGER")
                .priority(approval.getRiskLevel())
                .actionRequired(true)
                .groupId(approval.getIncidentId())
                .expiresAt(LocalDateTime.now().plusHours(1))
                .notificationData(Map.of(
                    "approval_id", approval.getId().toString(),
                    "incident_id", approval.getIncidentId(),
                    "tool_name", approval.getToolName(),
                    "risk_level", approval.getRiskLevel()
                ))
                .build();
            
            notifications.add(notification);
        }
        
        return approvalNotificationRepository.saveAll(notifications);
    }
    
    /**
     * Kafka 토픽에 샘플 이벤트 발송
     */
    private void sendSampleKafkaEvents(List<SecurityIncident> incidents, List<ThreatIndicator> indicators) {
        // KafkaTemplate이 없으면 Kafka 이벤트 발송 건너뛰기
        if (kafkaTemplate == null) {
            log.info("📋 Kafka가 구성되지 않아 이벤트 발송을 건너뜁니다.");
            return;
        }
        
        log.info("Kafka 토픽에 샘플 이벤트 발송 중...");
        
        // 보안 이벤트 발송 (계층 정보 포함)
        for (SecurityIncident incident : incidents) {
            // 계층 태그 추출
            String layerTag = incident.getTags().stream()
                .filter(tag -> tag.startsWith("layer"))
                .findFirst()
                .orElse("layer1"); // 기본값: layer1
            
            Map<String, Object> securityEvent = new HashMap<>();
            securityEvent.put("event_id", UUID.randomUUID().toString());
            securityEvent.put("incident_id", incident.getIncidentId());
            securityEvent.put("event_type", "SECURITY_INCIDENT");
            securityEvent.put("threat_level", incident.getThreatLevel().name());
            securityEvent.put("source_ip", incident.getSourceIp() != null ? incident.getSourceIp() : "Unknown");
            securityEvent.put("destination_ip", incident.getDestinationIp() != null ? incident.getDestinationIp() : "Unknown");
            securityEvent.put("description", incident.getDescription());
            securityEvent.put("timestamp", LocalDateTime.now().toString());
            securityEvent.put("organization_id", incident.getOrganizationId());
            securityEvent.put("risk_score", incident.getRiskScore());
            securityEvent.put("tier_layer", layerTag);  // 3계층 라우팅을 위한 계층 정보 추가
            securityEvent.put("tags", incident.getTags());  // 전체 태그 정보도 포함
            
            if (kafkaTemplate != null) {
                kafkaTemplate.send("security-events", incident.getIncidentId(), securityEvent);
            }
        }
        
        // 위협 지표 이벤트 발송 (계층 정보 포함)
        for (ThreatIndicator indicator : indicators) {
            // 계층 태그 추출
            String layerTag = indicator.getTags().stream()
                .filter(tag -> tag.startsWith("layer"))
                .findFirst()
                .orElse("layer1"); // 기본값: layer1
            
            Map<String, Object> threatEvent = new HashMap<>();
            threatEvent.put("event_id", UUID.randomUUID().toString());
            threatEvent.put("indicator_id", indicator.getIndicatorId());
            threatEvent.put("event_type", "THREAT_INDICATOR");
            threatEvent.put("indicator_type", indicator.getType().name());
            threatEvent.put("indicator_value", indicator.getValue());
            threatEvent.put("severity", indicator.getSeverity().name());
            threatEvent.put("confidence", indicator.getConfidence());
            threatEvent.put("source", indicator.getSource());
            threatEvent.put("timestamp", LocalDateTime.now().toString());
            threatEvent.put("tier_layer", layerTag);  // 3계층 라우팅을 위한 계층 정보 추가
            threatEvent.put("tags", indicator.getTags());
            
            if (kafkaTemplate != null) {
                kafkaTemplate.send("threat-indicators", indicator.getIndicatorId(), threatEvent);
            }
        }
        
        // 인증 이벤트 발송 (계층 정보 포함)
        Map<String, Object> authEvent = new HashMap<>();
        authEvent.put("event_id", UUID.randomUUID().toString());
        authEvent.put("event_type", "AUTHENTICATION");
        authEvent.put("user_id", "admin@company.com");
        authEvent.put("action", "LOGIN_FAILED");
        authEvent.put("source_ip", "203.0.113.45");
        authEvent.put("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        authEvent.put("timestamp", LocalDateTime.now().toString());
        authEvent.put("failure_reason", "INVALID_CREDENTIALS");
        authEvent.put("attempt_count", 5);
        authEvent.put("tier_layer", "layer1");  // 인증 실패는 Layer 1에서 빠른 차단
        authEvent.put("tags", Set.of("auth", "failed-login", "brute-force", "layer1"));
        if (kafkaTemplate != null) {
            kafkaTemplate.send("auth-events", "admin@company.com", authEvent);
        }
        
        // 네트워크 이벤트 발송 (계층 정보 포함)
        Map<String, Object> networkEvent = new HashMap<>();
        networkEvent.put("event_id", UUID.randomUUID().toString());
        networkEvent.put("event_type", "NETWORK_TRAFFIC");
        networkEvent.put("source_ip", "192.168.100.50");
        networkEvent.put("destination_ip", "203.0.113.45");
        networkEvent.put("source_port", 12345);
        networkEvent.put("destination_port", 443);
        networkEvent.put("protocol", "HTTPS");
        networkEvent.put("bytes_sent", 1024);
        networkEvent.put("bytes_received", 2048);
        networkEvent.put("timestamp", LocalDateTime.now().toString());
        networkEvent.put("classification", "SUSPICIOUS");
        networkEvent.put("tier_layer", "layer2");  // 네트워크 트래픽은 Layer 2 분석
        networkEvent.put("tags", Set.of("network", "suspicious", "outbound", "layer2"));
        if (kafkaTemplate != null) {
            kafkaTemplate.send("network-events", "192.168.100.50", networkEvent);
        }
        
        log.info("Kafka 이벤트 발송 완료");
    }
}