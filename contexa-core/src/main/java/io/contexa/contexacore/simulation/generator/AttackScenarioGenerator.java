package io.contexa.contexacore.simulation.generator;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.routing.AttackPattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 공격 시나리오 생성기
 * 
 * 다양한 실전 공격 시나리오를 생성하여 자율보안지능 시스템을 테스트합니다.
 * MITRE ATT&CK 프레임워크 기반으로 공격 패턴을 생성합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Component
public class AttackScenarioGenerator {
    
    // MITRE ATT&CK 기반 공격 유형
    public enum AttackType {
        BRUTE_FORCE("T1110", "Brute Force", 6.0),
        SQL_INJECTION("T1190", "Exploit Public-Facing Application", 7.5),
        PRIVILEGE_ESCALATION("T1068", "Exploitation for Privilege Escalation", 8.0),
        LATERAL_MOVEMENT("T1021", "Remote Services", 7.0),
        DATA_EXFILTRATION("T1041", "Exfiltration Over C2 Channel", 8.5),
        DDOS("T1498", "Network Denial of Service", 5.0),
        PHISHING("T1566", "Phishing", 6.5),
        MALWARE_DEPLOYMENT("T1055", "Process Injection", 9.0),
        ZERO_DAY("T1203", "Exploitation for Client Execution", 9.5),
        INSIDER_THREAT("T1078", "Valid Accounts", 7.5),
        RANSOMWARE("T1486", "Data Encrypted for Impact", 9.0),
        APT_CAMPAIGN("T1583", "Acquire Infrastructure", 8.5);
        
        private final String mitreId;
        private final String technique;
        private final double baseRiskScore;
        
        AttackType(String mitreId, String technique, double baseRiskScore) {
            this.mitreId = mitreId;
            this.technique = technique;
            this.baseRiskScore = baseRiskScore;
        }
        
        public String getMitreId() { return mitreId; }
        public String getTechnique() { return technique; }
        public double getBaseRiskScore() { return baseRiskScore; }
    }
    
    // IP 주소 풀 (공격자 시뮬레이션)
    private static final List<String> ATTACKER_IPS = Arrays.asList(
        "192.168.100.50", "192.168.100.51", "192.168.100.52",
        "10.0.0.100", "10.0.0.101", "172.16.0.50",
        "203.0.113.0", "198.51.100.0", "192.0.2.0"  // TEST-NET 주소
    );
    
    // 대상 시스템
    private static final List<String> TARGET_SYSTEMS = Arrays.asList(
        "web-server-01", "db-server-01", "api-gateway-01",
        "auth-service-01", "file-server-01", "mail-server-01"
    );
    
    // 사용자 계정 (내부자 위협 시뮬레이션)
    private static final List<String> USER_ACCOUNTS = Arrays.asList(
        "admin", "user01", "user02", "service_account",
        "developer01", "contractor01", "guest"
    );
    
    /**
     * 무작위 공격 시나리오 생성
     */
    public SecurityEvent generateRandomAttack() {
        AttackType[] types = AttackType.values();
        AttackType selectedType = types[ThreadLocalRandom.current().nextInt(types.length)];
        return generateAttack(selectedType);
    }
    
    /**
     * 특정 유형의 공격 시나리오 생성
     */
    public SecurityEvent generateAttack(AttackType type) {
        switch (type) {
            case BRUTE_FORCE:
                return generateBruteForceAttack();
            case SQL_INJECTION:
                return generateSQLInjectionAttack();
            case PRIVILEGE_ESCALATION:
                return generatePrivilegeEscalation();
            case LATERAL_MOVEMENT:
                return generateLateralMovement();
            case DATA_EXFILTRATION:
                return generateDataExfiltration();
            case DDOS:
                return generateDDoSAttack();
            case PHISHING:
                return generatePhishingAttack();
            case MALWARE_DEPLOYMENT:
                return generateMalwareDeployment();
            case ZERO_DAY:
                return generateZeroDayExploit();
            case INSIDER_THREAT:
                return generateInsiderThreat();
            case RANSOMWARE:
                return generateRansomwareAttack();
            case APT_CAMPAIGN:
                return generateAPTCampaign();
            default:
                return generateRandomAttack();
        }
    }
    
    /**
     * 무차별 대입 공격 생성
     */
    public SecurityEvent generateBruteForceAttack() {
        String eventId = UUID.randomUUID().toString();
        String sourceIp = getRandomItem(ATTACKER_IPS);
        String targetSystem = getRandomItem(TARGET_SYSTEMS);
        String targetAccount = getRandomItem(USER_ACCOUNTS);
        int attemptCount = ThreadLocalRandom.current().nextInt(50, 500);
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.BRUTE_FORCE.name());
        details.put("mitreId", AttackType.BRUTE_FORCE.getMitreId());
        details.put("technique", AttackType.BRUTE_FORCE.getTechnique());
        details.put("sourceIp", sourceIp);
        details.put("targetSystem", targetSystem);
        details.put("targetAccount", targetAccount);
        details.put("attemptCount", attemptCount);
        details.put("timeWindow", "5 minutes");
        details.put("protocol", "SSH");
        
        double riskScore = AttackType.BRUTE_FORCE.getBaseRiskScore() + 
                          (attemptCount > 100 ? 1.0 : 0) +
                          (attemptCount > 300 ? 1.0 : 0);
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.BRUTE_FORCE)
            .severity(riskScore > 7 ? SecurityEvent.Severity.HIGH : SecurityEvent.Severity.MEDIUM)
            .sourceIp(sourceIp)
            .targetSystem(targetSystem)
            .description(String.format("Brute force attack detected: %d login attempts from %s to %s@%s", 
                attemptCount, sourceIp, targetAccount, targetSystem))
            .riskScore(Math.min(riskScore, 10.0))
            .confidenceScore(0.85)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * SQL Injection 공격 생성
     */
    public SecurityEvent generateSQLInjectionAttack() {
        String eventId = UUID.randomUUID().toString();
        String sourceIp = getRandomItem(ATTACKER_IPS);
        String targetSystem = "web-server-01";
        
        List<String> payloads = Arrays.asList(
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "UNION SELECT * FROM passwords",
            "' AND 1=0 UNION ALL SELECT NULL",
            "admin' --"
        );
        
        String payload = getRandomItem(payloads);
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.SQL_INJECTION.name());
        details.put("mitreId", AttackType.SQL_INJECTION.getMitreId());
        details.put("technique", AttackType.SQL_INJECTION.getTechnique());
        details.put("sourceIp", sourceIp);
        details.put("targetSystem", targetSystem);
        details.put("endpoint", "/api/login");
        details.put("parameter", "username");
        details.put("payload", payload);
        details.put("httpMethod", "POST");
        details.put("userAgent", "Mozilla/5.0 (compatible; SQLMap/1.5)");
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.SQL_INJECTION_ATTACK)
            .severity(SecurityEvent.Severity.HIGH)
            .sourceIp(sourceIp)
            .targetSystem(targetSystem)
            .description(String.format("SQL injection attempt detected from %s: payload='%s'", 
                sourceIp, payload))
            .riskScore(AttackType.SQL_INJECTION.getBaseRiskScore())
            .confidenceScore(0.90)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 권한 상승 공격 생성
     */
    public SecurityEvent generatePrivilegeEscalation() {
        String eventId = UUID.randomUUID().toString();
        String sourceUser = getRandomItem(USER_ACCOUNTS);
        String targetSystem = getRandomItem(TARGET_SYSTEMS);
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.PRIVILEGE_ESCALATION.name());
        details.put("mitreId", AttackType.PRIVILEGE_ESCALATION.getMitreId());
        details.put("technique", AttackType.PRIVILEGE_ESCALATION.getTechnique());
        details.put("sourceUser", sourceUser);
        details.put("targetSystem", targetSystem);
        details.put("originalPrivilege", "user");
        details.put("targetPrivilege", "root");
        details.put("exploitType", "kernel_vulnerability");
        details.put("cve", "CVE-2024-" + ThreadLocalRandom.current().nextInt(10000, 99999));
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.PRIVILEGE_ESCALATION)
            .severity(SecurityEvent.Severity.HIGH)
            .sourceIp("127.0.0.1")
            .targetSystem(targetSystem)
            .description(String.format("Privilege escalation attempt by user %s on %s", 
                sourceUser, targetSystem))
            .riskScore(AttackType.PRIVILEGE_ESCALATION.getBaseRiskScore())
            .confidenceScore(0.88)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 측면 이동 공격 생성
     */
    public SecurityEvent generateLateralMovement() {
        String eventId = UUID.randomUUID().toString();
        String sourceSystem = getRandomItem(TARGET_SYSTEMS);
        String targetSystem = getRandomItem(TARGET_SYSTEMS);
        while (targetSystem.equals(sourceSystem)) {
            targetSystem = getRandomItem(TARGET_SYSTEMS);
        }
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.LATERAL_MOVEMENT.name());
        details.put("mitreId", AttackType.LATERAL_MOVEMENT.getMitreId());
        details.put("technique", AttackType.LATERAL_MOVEMENT.getTechnique());
        details.put("sourceSystem", sourceSystem);
        details.put("targetSystem", targetSystem);
        details.put("protocol", "RDP");
        details.put("credentialType", "pass-the-hash");
        details.put("accountUsed", "domain_admin");
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.LATERAL_MOVEMENT)
            .severity(SecurityEvent.Severity.HIGH)
            .sourceIp("192.168.1.100")
            .targetSystem(targetSystem)
            .description(String.format("Lateral movement detected from %s to %s using RDP", 
                sourceSystem, targetSystem))
            .riskScore(AttackType.LATERAL_MOVEMENT.getBaseRiskScore())
            .confidenceScore(0.82)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 데이터 유출 공격 생성
     */
    public SecurityEvent generateDataExfiltration() {
        String eventId = UUID.randomUUID().toString();
        String sourceSystem = getRandomItem(TARGET_SYSTEMS);
        String destinationIp = getRandomItem(ATTACKER_IPS);
        long dataSize = ThreadLocalRandom.current().nextLong(100_000_000, 10_000_000_000L);
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.DATA_EXFILTRATION.name());
        details.put("mitreId", AttackType.DATA_EXFILTRATION.getMitreId());
        details.put("technique", AttackType.DATA_EXFILTRATION.getTechnique());
        details.put("sourceSystem", sourceSystem);
        details.put("destinationIp", destinationIp);
        details.put("protocol", "HTTPS");
        details.put("dataSize", dataSize);
        details.put("dataSizeGB", dataSize / (1024.0 * 1024.0 * 1024.0));
        details.put("encryptionUsed", true);
        details.put("exfiltrationMethod", "cloud_storage");
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.DATA_EXFILTRATION)
            .severity(SecurityEvent.Severity.CRITICAL)
            .sourceIp("192.168.1.50")
            .targetSystem(sourceSystem)
            .description(String.format("Data exfiltration detected: %.2f GB transferred from %s to %s", 
                dataSize / (1024.0 * 1024.0 * 1024.0), sourceSystem, destinationIp))
            .riskScore(AttackType.DATA_EXFILTRATION.getBaseRiskScore())
            .confidenceScore(0.91)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * DDoS 공격 생성
     */
    public SecurityEvent generateDDoSAttack() {
        String eventId = UUID.randomUUID().toString();
        String targetSystem = "web-server-01";
        int botnetSize = ThreadLocalRandom.current().nextInt(1000, 50000);
        int requestsPerSecond = ThreadLocalRandom.current().nextInt(10000, 1000000);
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.DDOS.name());
        details.put("mitreId", AttackType.DDOS.getMitreId());
        details.put("technique", AttackType.DDOS.getTechnique());
        details.put("targetSystem", targetSystem);
        details.put("attackVector", "HTTP_FLOOD");
        details.put("botnetSize", botnetSize);
        details.put("requestsPerSecond", requestsPerSecond);
        details.put("targetPort", 443);
        details.put("duration", "ongoing");
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.DDOS_ATTACK)
            .severity(SecurityEvent.Severity.HIGH)
            .sourceIp("multiple")
            .targetSystem(targetSystem)
            .description(String.format("DDoS attack in progress: %d bots, %d req/s targeting %s", 
                botnetSize, requestsPerSecond, targetSystem))
            .riskScore(AttackType.DDOS.getBaseRiskScore())
            .confidenceScore(0.95)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 피싱 공격 생성
     */
    public SecurityEvent generatePhishingAttack() {
        String eventId = UUID.randomUUID().toString();
        String targetEmail = getRandomItem(USER_ACCOUNTS) + "@company.com";
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.PHISHING.name());
        details.put("mitreId", AttackType.PHISHING.getMitreId());
        details.put("technique", AttackType.PHISHING.getTechnique());
        details.put("targetEmail", targetEmail);
        details.put("senderEmail", "security@companny.com");  // 의도적 오타
        details.put("subject", "Urgent: Security Update Required");
        details.put("maliciousUrl", "http://evil-site.com/login");
        details.put("attachmentName", "security_update.exe");
        details.put("spfCheck", "fail");
        details.put("dkimCheck", "fail");
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.PHISHING_ATTEMPT)
            .severity(SecurityEvent.Severity.MEDIUM)
            .sourceIp("203.0.113.100")
            .targetSystem("mail-server-01")
            .description(String.format("Phishing email detected targeting %s with malicious attachment", 
                targetEmail))
            .riskScore(AttackType.PHISHING.getBaseRiskScore())
            .confidenceScore(0.87)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 악성코드 배포 생성
     */
    public SecurityEvent generateMalwareDeployment() {
        String eventId = UUID.randomUUID().toString();
        String targetSystem = getRandomItem(TARGET_SYSTEMS);
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.MALWARE_DEPLOYMENT.name());
        details.put("mitreId", AttackType.MALWARE_DEPLOYMENT.getMitreId());
        details.put("technique", AttackType.MALWARE_DEPLOYMENT.getTechnique());
        details.put("targetSystem", targetSystem);
        details.put("malwareType", "trojan");
        details.put("malwareName", "Emotet");
        details.put("injectionMethod", "process_hollowing");
        details.put("targetProcess", "svchost.exe");
        details.put("persistenceMethod", "registry_autostart");
        details.put("c2Server", "192.0.2.100:8443");
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.MALWARE_DEPLOYMENT)
            .severity(SecurityEvent.Severity.CRITICAL)
            .sourceIp("127.0.0.1")
            .targetSystem(targetSystem)
            .description(String.format("Malware deployment detected on %s: Emotet trojan with C2 communication", 
                targetSystem))
            .riskScore(AttackType.MALWARE_DEPLOYMENT.getBaseRiskScore())
            .confidenceScore(0.93)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * Zero-day 익스플로잇 생성
     */
    public SecurityEvent generateZeroDayExploit() {
        String eventId = UUID.randomUUID().toString();
        String targetSystem = getRandomItem(TARGET_SYSTEMS);
        String sourceIp = getRandomItem(ATTACKER_IPS);
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.ZERO_DAY.name());
        details.put("mitreId", AttackType.ZERO_DAY.getMitreId());
        details.put("technique", AttackType.ZERO_DAY.getTechnique());
        details.put("sourceIp", sourceIp);
        details.put("targetSystem", targetSystem);
        details.put("vulnerabilityType", "remote_code_execution");
        details.put("affectedSoftware", "Apache Log4j");
        details.put("exploitComplexity", "low");
        details.put("exploitReliability", "high");
        details.put("payloadDelivered", true);
        details.put("sandboxEvasion", true);
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.ZERO_DAY_EXPLOIT)
            .severity(SecurityEvent.Severity.CRITICAL)
            .sourceIp(sourceIp)
            .targetSystem(targetSystem)
            .description(String.format("Zero-day exploit detected targeting %s: Unknown vulnerability in Apache Log4j", 
                targetSystem))
            .riskScore(AttackType.ZERO_DAY.getBaseRiskScore())
            .confidenceScore(0.75)  // 낮은 신뢰도 (알려지지 않은 공격)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 내부자 위협 생성
     */
    public SecurityEvent generateInsiderThreat() {
        String eventId = UUID.randomUUID().toString();
        String insiderUser = getRandomItem(USER_ACCOUNTS);
        String targetSystem = "file-server-01";
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.INSIDER_THREAT.name());
        details.put("mitreId", AttackType.INSIDER_THREAT.getMitreId());
        details.put("technique", AttackType.INSIDER_THREAT.getTechnique());
        details.put("insiderUser", insiderUser);
        details.put("targetSystem", targetSystem);
        details.put("anomalyType", "unusual_access_pattern");
        details.put("filesAccessed", ThreadLocalRandom.current().nextInt(100, 1000));
        details.put("afterHours", true);
        details.put("dataClassification", "confidential");
        details.put("previousBehaviorScore", 0.2);
        details.put("currentBehaviorScore", 0.85);
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.INSIDER_THREAT)
            .severity(SecurityEvent.Severity.HIGH)
            .sourceIp("192.168.1.50")
            .targetSystem(targetSystem)
            .description(String.format("Insider threat detected: User %s accessing sensitive data after hours", 
                insiderUser))
            .riskScore(AttackType.INSIDER_THREAT.getBaseRiskScore())
            .confidenceScore(0.78)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 랜섬웨어 공격 생성
     */
    public SecurityEvent generateRansomwareAttack() {
        String eventId = UUID.randomUUID().toString();
        String targetSystem = getRandomItem(TARGET_SYSTEMS);
        int filesEncrypted = ThreadLocalRandom.current().nextInt(1000, 50000);
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.RANSOMWARE.name());
        details.put("mitreId", AttackType.RANSOMWARE.getMitreId());
        details.put("technique", AttackType.RANSOMWARE.getTechnique());
        details.put("targetSystem", targetSystem);
        details.put("ransomwareFamily", "LockBit");
        details.put("filesEncrypted", filesEncrypted);
        details.put("encryptionAlgorithm", "AES-256");
        details.put("ransomNote", "ransom_note.txt");
        details.put("bitcoinAddress", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        details.put("ransomAmount", "$500,000");
        details.put("shadowCopiesDeleted", true);
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.RANSOMWARE_ATTACK)
            .severity(SecurityEvent.Severity.CRITICAL)
            .sourceIp("127.0.0.1")
            .targetSystem(targetSystem)
            .description(String.format("Ransomware attack in progress on %s: %d files encrypted by LockBit", 
                targetSystem, filesEncrypted))
            .riskScore(AttackType.RANSOMWARE.getBaseRiskScore())
            .confidenceScore(0.96)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * APT 캠페인 생성 (다단계 공격)
     */
    public SecurityEvent generateAPTCampaign() {
        String eventId = UUID.randomUUID().toString();
        String campaignId = "APT-" + ThreadLocalRandom.current().nextInt(1, 100);
        
        List<String> stages = Arrays.asList(
            "initial_compromise",
            "establish_foothold",
            "escalate_privileges",
            "internal_recon",
            "lateral_movement",
            "maintain_presence",
            "complete_mission"
        );
        
        String currentStage = stages.get(ThreadLocalRandom.current().nextInt(stages.size()));
        
        Map<String, Object> details = new HashMap<>();
        details.put("attackType", AttackType.APT_CAMPAIGN.name());
        details.put("mitreId", AttackType.APT_CAMPAIGN.getMitreId());
        details.put("technique", AttackType.APT_CAMPAIGN.getTechnique());
        details.put("campaignId", campaignId);
        details.put("threatActor", "Lazarus Group");
        details.put("currentStage", currentStage);
        details.put("stagesCompleted", stages.indexOf(currentStage));
        details.put("totalStages", stages.size());
        details.put("duration", ThreadLocalRandom.current().nextInt(1, 365) + " days");
        details.put("sophistication", "high");
        details.put("targetedData", "intellectual_property");
        
        return SecurityEvent.builder()
            .eventId(eventId)
            .eventType(SecurityEvent.EventType.APT_CAMPAIGN)
            .severity(SecurityEvent.Severity.CRITICAL)
            .sourceIp("multiple")
            .targetSystem("multiple")
            .description(String.format("APT campaign %s detected: Stage '%s' by Lazarus Group", 
                campaignId, currentStage))
            .riskScore(AttackType.APT_CAMPAIGN.getBaseRiskScore())
            .confidenceScore(0.72)  // APT는 탐지가 어려움
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * AttackPattern 엔티티 생성 (3-Tier 라우터용)
     */
    public AttackPattern generateAttackPattern(SecurityEvent event) {
        AttackPattern pattern = new AttackPattern();
        pattern.setSourceIp(event.getSourceIp());
        pattern.setPattern(event.getEventType().toString());
        pattern.setAttackType(event.getEventType().toString());
        pattern.setSeverity(event.getSeverity().toString());
        // AttackPattern에는 riskScore 필드가 없음
        pattern.setConfidenceScore(event.getConfidenceScore() != null ? event.getConfidenceScore() : 0.0);
        pattern.setDetectedAt(event.getTimestamp());
        pattern.setLastSeenAt(event.getTimestamp());
        pattern.setAttemptCount(1);
        pattern.setBlocked(false);
        
        // MITRE ATT&CK 정보 추가
        if (event.getDetails() != null) {
            // AttackPattern에는 mitreId 필드가 없고 mitreTactic, mitreTechnique만 있음
            pattern.setMitreTactic((String) event.getDetails().get("mitreTactic"));
            pattern.setMitreTechnique((String) event.getDetails().get("technique"));
        }
        
        return pattern;
    }
    
    /**
     * 복합 공격 시나리오 생성 (여러 단계의 연관된 공격)
     */
    public List<SecurityEvent> generateComplexAttackScenario() {
        List<SecurityEvent> scenario = new ArrayList<>();
        
        // 1단계: 정찰 (피싱)
        scenario.add(generatePhishingAttack());
        
        // 2단계: 초기 침투 (악성코드)
        scenario.add(generateMalwareDeployment());
        
        // 3단계: 권한 상승
        scenario.add(generatePrivilegeEscalation());
        
        // 4단계: 측면 이동
        scenario.add(generateLateralMovement());
        
        // 5단계: 데이터 유출
        scenario.add(generateDataExfiltration());
        
        // 모든 이벤트에 동일한 캠페인 ID 부여
        String campaignId = "CAMPAIGN-" + UUID.randomUUID().toString().substring(0, 8);
        scenario.forEach(event -> {
            if (event.getDetails() == null) {
                event.setDetails(new HashMap<>());
            }
            event.getDetails().put("campaignId", campaignId);
        });
        
        log.info("복합 공격 시나리오 생성: {} 단계, 캠페인 ID: {}", scenario.size(), campaignId);
        
        return scenario;
    }
    
    // 유틸리티 메서드
    private <T> T getRandomItem(List<T> list) {
        return list.get(ThreadLocalRandom.current().nextInt(list.size()));
    }
}