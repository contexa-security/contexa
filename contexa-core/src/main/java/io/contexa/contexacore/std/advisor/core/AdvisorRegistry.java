package io.contexa.contexacore.std.advisor.core;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.advisor.api.Advisor;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Advisor 레지스트리
 * 
 * 모든 Advisor를 중앙에서 관리하고 체인을 구성합니다.
 * - 동적 등록/해제
 * - 도메인별 조회
 * - 체인 프로파일 기반 구성
 */
@Slf4j
@Component
public class AdvisorRegistry {
    
    /**
     * 모든 등록된 Advisor (name -> advisor)
     */
    private final Map<String, BaseAdvisor> advisors = new ConcurrentHashMap<>();
    
    /**
     * 도메인별 Advisor 그룹 (domain -> list of advisors)
     */
    private final Map<String, List<BaseAdvisor>> domainAdvisors = new ConcurrentHashMap<>();
    
    /**
     * 체인 프로파일 설정
     */
    private final Map<ChainProfile, List<String>> chainProfiles = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void init() {
        log.info("AdvisorRegistry 초기화");
        
        // 기본 체인 프로파일 설정
        initializeDefaultProfiles();
    }
    
    /**
     * Advisor 등록
     */
    public synchronized void register(BaseAdvisor advisor) {
        if (advisor == null) {
            throw new IllegalArgumentException("Advisor cannot be null");
        }
        
        if (!advisor.validate()) {
            throw new IllegalArgumentException("Invalid advisor configuration: " + advisor);
        }
        
        String name = advisor.getName();
        String domain = advisor.getDomain();
        
        // 전체 레지스트리에 등록
        advisors.put(name, advisor);
        
        // 도메인별 그룹에 추가
        domainAdvisors.computeIfAbsent(domain, k -> new ArrayList<>()).add(advisor);
        
        log.info("Advisor 등록: {} (domain: {}, order: {})",
            name, domain, advisor.getOrder());
    }
    
    /**
     * 여러 Advisor 일괄 등록
     */
    public void registerAll(Collection<? extends BaseAdvisor> advisorList) {
        for (BaseAdvisor advisor : advisorList) {
            register(advisor);
        }
    }
    
    /**
     * Advisor 해제
     */
    public synchronized void unregister(String advisorName) {
        BaseAdvisor advisor = advisors.remove(advisorName);
        
        if (advisor != null) {
            String domain = advisor.getDomain();
            List<BaseAdvisor> domainList = domainAdvisors.get(domain);
            
            if (domainList != null) {
                domainList.remove(advisor);
                
                if (domainList.isEmpty()) {
                    domainAdvisors.remove(domain);
                }
            }
            
            log.info("Advisor 해제: {}", advisorName);
        }
    }
    
    /**
     * 특정 Advisor 조회
     */
    public Optional<BaseAdvisor> get(String advisorName) {
        return Optional.ofNullable(advisors.get(advisorName));
    }
    
    /**
     * 도메인별 Advisor 조회
     */
    public List<BaseAdvisor> getByDomain(String domain) {
        return domainAdvisors.getOrDefault(domain, Collections.emptyList())
            .stream()
            .sorted(Comparator.comparingInt(BaseAdvisor::getOrder))
            .collect(Collectors.toList());
    }
    
    /**
     * 활성화된 Advisor만 조회
     */
    public List<BaseAdvisor> getEnabled() {
        return advisors.values().stream()
            .filter(BaseAdvisor::isEnabled)
            .sorted(Comparator.comparingInt(BaseAdvisor::getOrder))
            .collect(Collectors.toList());
    }
    
    /**
     * 체인 프로파일 기반 Advisor 체인 구성
     */
    public List<Advisor> buildChain(ChainProfile profile) {
        List<String> advisorNames = chainProfiles.get(profile);
        
        if (advisorNames == null || advisorNames.isEmpty()) {
            log.warn("No chain profile found for: {}", profile);
            return Collections.emptyList();
        }
        
        List<Advisor> chain = new ArrayList<>();
        
        for (String name : advisorNames) {
            // 와일드카드 처리 (예: "soar.*" -> 모든 SOAR 도메인 Advisor)
            if (name.endsWith(".*")) {
                String domain = name.substring(0, name.length() - 2);
                chain.addAll(getByDomain(domain));
            } else {
                get(name).ifPresent(chain::add);
            }
        }
        
        // Order 기준으로 정렬
        chain.sort(Comparator.comparingInt(Advisor::getOrder));
        
        log.info("체인 구성 완료 [{}]: {} 개 Advisor", profile, chain.size());
        chain.forEach(a -> log.debug("  - {} (order: {})", a.getName(), a.getOrder()));
        
        return chain;
    }
    
    /**
     * 커스텀 체인 구성
     */
    public List<Advisor> buildCustomChain(String... advisorNames) {
        List<Advisor> chain = new ArrayList<>();
        
        for (String name : advisorNames) {
            get(name).ifPresent(chain::add);
        }
        
        chain.sort(Comparator.comparingInt(Advisor::getOrder));
        return chain;
    }
    
    /**
     * 체인 프로파일 추가/업데이트
     */
    public void defineProfile(ChainProfile profile, List<String> advisorNames) {
        chainProfiles.put(profile, new ArrayList<>(advisorNames));
        log.info("체인 프로파일 정의: {} -> {}", profile, advisorNames);
    }
    
    /**
     * 체인 프로파일 추가/업데이트 (가변 인자)
     */
    public void defineProfile(ChainProfile profile, String... advisorNames) {
        defineProfile(profile, Arrays.asList(advisorNames));
    }
    
    /**
     * 등록된 모든 도메인 조회
     */
    public Set<String> getDomains() {
        return new HashSet<>(domainAdvisors.keySet());
    }
    
    /**
     * 등록된 Advisor 통계
     */
    public RegistryStats getStats() {
        Map<String, Integer> domainCounts = new HashMap<>();
        for (Map.Entry<String, List<BaseAdvisor>> entry : domainAdvisors.entrySet()) {
            domainCounts.put(entry.getKey(), entry.getValue().size());
        }
        
        return new RegistryStats(
            advisors.size(),
            domainAdvisors.size(),
            domainCounts,
            chainProfiles.keySet()
        );
    }
    
    /**
     * 모든 Advisor 활성화
     */
    public void enableAll() {
        advisors.values().forEach(advisor -> advisor.setEnabled(true));
        log.info("모든 Advisor 활성화");
    }
    
    /**
     * 모든 Advisor 비활성화
     */
    public void disableAll() {
        advisors.values().forEach(advisor -> advisor.setEnabled(false));
        log.info("모든 Advisor 비활성화");
    }
    
    /**
     * 도메인별 활성화
     */
    public void enableDomain(String domain) {
        List<BaseAdvisor> domainList = domainAdvisors.get(domain);
        if (domainList != null) {
            domainList.forEach(advisor -> advisor.setEnabled(true));
            log.info("도메인 {} Advisor 활성화", domain);
        }
    }
    
    /**
     * 도메인별 비활성화
     */
    public void disableDomain(String domain) {
        List<BaseAdvisor> domainList = domainAdvisors.get(domain);
        if (domainList != null) {
            domainList.forEach(advisor -> advisor.setEnabled(false));
            log.info("도메인 {} Advisor 비활성화", domain);
        }
    }
    
    /**
     * 기본 체인 프로파일 초기화
     */
    private void initializeDefaultProfiles() {
        // STANDARD: 기본 보안 체인
        defineProfile(ChainProfile.STANDARD,
            "iam.authorization",
            "soar.metrics"
        );
        
        // SECURITY_CRITICAL: 높은 보안 요구사항
        defineProfile(ChainProfile.SECURITY_CRITICAL,
            "threat.detection",
            "iam.authorization",
            "iam.role",
            "soar.approval",
            "compliance.audit"
        );
        
        // COMPLIANCE: 규정 준수 중심
        defineProfile(ChainProfile.COMPLIANCE,
            "iam.authorization",
            "compliance.validation",
            "compliance.audit",
            "compliance.reporting"
        );
        
        // PERFORMANCE: 성능 최적화 (최소 Advisor)
        defineProfile(ChainProfile.PERFORMANCE,
            "iam.authorization"
        );
        
        // FULL: 모든 Advisor 활성화
        defineProfile(ChainProfile.FULL,
            "threat.*",
            "iam.*",
            "soar.*",
            "compliance.*"
        );
        
        log.info("기본 체인 프로파일 초기화 완료");
    }
    
    /**
     * 체인 프로파일 열거형
     */
    public enum ChainProfile {
        STANDARD,           // 표준 보안 체인
        SECURITY_CRITICAL,  // 높은 보안 요구사항
        COMPLIANCE,         // 규정 준수 중심
        PERFORMANCE,        // 성능 최적화
        FULL,              // 모든 기능 활성화
        CUSTOM             // 사용자 정의
    }
    
    /**
     * 레지스트리 통계
     */
    public static class RegistryStats {
        public final int totalAdvisors;
        public final int totalDomains;
        public final Map<String, Integer> advisorsPerDomain;
        public final Set<ChainProfile> availableProfiles;
        
        public RegistryStats(int totalAdvisors, int totalDomains,
                            Map<String, Integer> advisorsPerDomain,
                            Set<ChainProfile> availableProfiles) {
            this.totalAdvisors = totalAdvisors;
            this.totalDomains = totalDomains;
            this.advisorsPerDomain = advisorsPerDomain;
            this.availableProfiles = availableProfiles;
        }
        
        @Override
        public String toString() {
            return String.format("RegistryStats[advisors=%d, domains=%d, profiles=%d]",
                totalAdvisors, totalDomains, availableProfiles.size());
        }
    }
}