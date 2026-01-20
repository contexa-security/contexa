package io.contexa.contexacore.std.advisor.core;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.advisor.api.Advisor;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;


@Slf4j
public class AdvisorRegistry {
    
    
    private final Map<String, BaseAdvisor> advisors = new ConcurrentHashMap<>();
    
    
    private final Map<String, List<BaseAdvisor>> domainAdvisors = new ConcurrentHashMap<>();
    
    
    private final Map<ChainProfile, List<String>> chainProfiles = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void init() {
        log.info("AdvisorRegistry 초기화");
        
        
        initializeDefaultProfiles();
    }
    
    
    public synchronized void register(BaseAdvisor advisor) {
        if (advisor == null) {
            throw new IllegalArgumentException("Advisor cannot be null");
        }
        
        if (!advisor.validate()) {
            throw new IllegalArgumentException("Invalid advisor configuration: " + advisor);
        }
        
        String name = advisor.getName();
        String domain = advisor.getDomain();
        
        
        advisors.put(name, advisor);
        
        
        domainAdvisors.computeIfAbsent(domain, k -> new ArrayList<>()).add(advisor);
        
        log.info("Advisor 등록: {} (domain: {}, order: {})",
            name, domain, advisor.getOrder());
    }
    
    
    public void registerAll(Collection<? extends BaseAdvisor> advisorList) {
        for (BaseAdvisor advisor : advisorList) {
            register(advisor);
        }
    }
    
    
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
    
    
    public Optional<BaseAdvisor> get(String advisorName) {
        return Optional.ofNullable(advisors.get(advisorName));
    }
    
    
    public List<BaseAdvisor> getByDomain(String domain) {
        return domainAdvisors.getOrDefault(domain, Collections.emptyList())
            .stream()
            .sorted(Comparator.comparingInt(BaseAdvisor::getOrder))
            .collect(Collectors.toList());
    }
    
    
    public List<BaseAdvisor> getEnabled() {
        return advisors.values().stream()
            .filter(BaseAdvisor::isEnabled)
            .sorted(Comparator.comparingInt(BaseAdvisor::getOrder))
            .collect(Collectors.toList());
    }
    
    
    public List<Advisor> buildChain(ChainProfile profile) {
        List<String> advisorNames = chainProfiles.get(profile);
        
        if (advisorNames == null || advisorNames.isEmpty()) {
            log.warn("No chain profile found for: {}", profile);
            return Collections.emptyList();
        }
        
        List<Advisor> chain = new ArrayList<>();
        
        for (String name : advisorNames) {
            
            if (name.endsWith(".*")) {
                String domain = name.substring(0, name.length() - 2);
                chain.addAll(getByDomain(domain));
            } else {
                get(name).ifPresent(chain::add);
            }
        }
        
        
        chain.sort(Comparator.comparingInt(Advisor::getOrder));
        
        log.info("체인 구성 완료 [{}]: {} 개 Advisor", profile, chain.size());
        chain.forEach(a -> log.debug("  - {} (order: {})", a.getName(), a.getOrder()));
        
        return chain;
    }
    
    
    public List<Advisor> buildCustomChain(String... advisorNames) {
        List<Advisor> chain = new ArrayList<>();
        
        for (String name : advisorNames) {
            get(name).ifPresent(chain::add);
        }
        
        chain.sort(Comparator.comparingInt(Advisor::getOrder));
        return chain;
    }
    
    
    public void defineProfile(ChainProfile profile, List<String> advisorNames) {
        chainProfiles.put(profile, new ArrayList<>(advisorNames));
        log.info("체인 프로파일 정의: {} -> {}", profile, advisorNames);
    }
    
    
    public void defineProfile(ChainProfile profile, String... advisorNames) {
        defineProfile(profile, Arrays.asList(advisorNames));
    }
    
    
    public Set<String> getDomains() {
        return new HashSet<>(domainAdvisors.keySet());
    }
    
    
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
    
    
    public void enableAll() {
        advisors.values().forEach(advisor -> advisor.setEnabled(true));
        log.info("모든 Advisor 활성화");
    }
    
    
    public void disableAll() {
        advisors.values().forEach(advisor -> advisor.setEnabled(false));
        log.info("모든 Advisor 비활성화");
    }
    
    
    public void enableDomain(String domain) {
        List<BaseAdvisor> domainList = domainAdvisors.get(domain);
        if (domainList != null) {
            domainList.forEach(advisor -> advisor.setEnabled(true));
            log.info("도메인 {} Advisor 활성화", domain);
        }
    }
    
    
    public void disableDomain(String domain) {
        List<BaseAdvisor> domainList = domainAdvisors.get(domain);
        if (domainList != null) {
            domainList.forEach(advisor -> advisor.setEnabled(false));
            log.info("도메인 {} Advisor 비활성화", domain);
        }
    }
    
    
    private void initializeDefaultProfiles() {
        
        defineProfile(ChainProfile.STANDARD,
            "iam.authorization",
            "soar.metrics"
        );
        
        
        defineProfile(ChainProfile.SECURITY_CRITICAL,
            "threat.detection",
            "iam.authorization",
            "iam.role",
            "soar.approval",
            "compliance.audit"
        );
        
        
        defineProfile(ChainProfile.COMPLIANCE,
            "iam.authorization",
            "compliance.validation",
            "compliance.audit",
            "compliance.reporting"
        );
        
        
        defineProfile(ChainProfile.PERFORMANCE,
            "iam.authorization"
        );
        
        
        defineProfile(ChainProfile.FULL,
            "threat.*",
            "iam.*",
            "soar.*",
            "compliance.*"
        );
        
        log.info("기본 체인 프로파일 초기화 완료");
    }
    
    
    public enum ChainProfile {
        STANDARD,           
        SECURITY_CRITICAL,  
        COMPLIANCE,         
        PERFORMANCE,        
        FULL,              
        CUSTOM             
    }
    
    
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