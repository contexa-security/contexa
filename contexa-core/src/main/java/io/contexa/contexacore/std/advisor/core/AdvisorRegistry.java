package io.contexa.contexacore.std.advisor.core;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.advisor.api.Advisor;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
public class AdvisorRegistry {

    private final Map<String, Advisor> advisors = new ConcurrentHashMap<>();
    private final Map<String, List<Advisor>> domainAdvisors = new ConcurrentHashMap<>();

    public synchronized void register(Advisor advisor) {
        if (advisor == null) {
            throw new IllegalArgumentException("Advisor cannot be null");
        }

        String name = advisor.getName();
        advisors.put(name, advisor);

        if (advisor instanceof BaseAdvisor baseAdvisor) {
            if (!baseAdvisor.validate()) {
                advisors.remove(name);
                throw new IllegalArgumentException("Invalid advisor configuration: " + advisor);
            }
            String domain = baseAdvisor.getDomain();
            domainAdvisors.computeIfAbsent(domain, k -> new ArrayList<>()).add(advisor);
        }
    }

    public void registerAll(Collection<? extends Advisor> advisorList) {
        for (Advisor advisor : advisorList) {
            register(advisor);
        }
    }

    public synchronized void unregister(String advisorName) {
        Advisor advisor = advisors.remove(advisorName);

        if (advisor instanceof BaseAdvisor baseAdvisor) {
            String domain = baseAdvisor.getDomain();
            List<Advisor> domainList = domainAdvisors.get(domain);

            if (domainList != null) {
                domainList.remove(advisor);

                if (domainList.isEmpty()) {
                    domainAdvisors.remove(domain);
                }
            }
        }
    }

    public Optional<Advisor> get(String advisorName) {
        return Optional.ofNullable(advisors.get(advisorName));
    }

    public List<Advisor> getByDomain(String domain) {
        return domainAdvisors.getOrDefault(domain, Collections.emptyList())
                .stream()
                .sorted(Comparator.comparingInt(Advisor::getOrder))
                .collect(Collectors.toList());
    }

    public List<Advisor> getEnabled() {
        return advisors.values().stream()
                .filter(this::isAdvisorEnabled)
                .sorted(Comparator.comparingInt(Advisor::getOrder))
                .collect(Collectors.toList());
    }

    private boolean isAdvisorEnabled(Advisor advisor) {
        if (advisor instanceof BaseAdvisor baseAdvisor) {
            return baseAdvisor.isEnabled();
        }
        return true;
    }

    public Set<String> getDomains() {
        return new HashSet<>(domainAdvisors.keySet());
    }

    public RegistryStats getStats() {
        Map<String, Integer> domainCounts = new HashMap<>();
        for (Map.Entry<String, List<Advisor>> entry : domainAdvisors.entrySet()) {
            domainCounts.put(entry.getKey(), entry.getValue().size());
        }

        return new RegistryStats(
                advisors.size(),
                domainAdvisors.size(),
                domainCounts
        );
    }

    public void enableAll() {
        advisors.values().forEach(advisor -> {
            if (advisor instanceof BaseAdvisor baseAdvisor) {
                baseAdvisor.setEnabled(true);
            }
        });
    }

    public void disableAll() {
        advisors.values().forEach(advisor -> {
            if (advisor instanceof BaseAdvisor baseAdvisor) {
                baseAdvisor.setEnabled(false);
            }
        });
    }

    public void enableDomain(String domain) {
        List<Advisor> domainList = domainAdvisors.get(domain);
        if (domainList != null) {
            domainList.forEach(advisor -> {
                if (advisor instanceof BaseAdvisor baseAdvisor) {
                    baseAdvisor.setEnabled(true);
                }
            });
        }
    }

    public void disableDomain(String domain) {
        List<Advisor> domainList = domainAdvisors.get(domain);
        if (domainList != null) {
            domainList.forEach(advisor -> {
                if (advisor instanceof BaseAdvisor baseAdvisor) {
                    baseAdvisor.setEnabled(false);
                }
            });
        }
    }

    public static class RegistryStats {
        public final int totalAdvisors;
        public final int totalDomains;
        public final Map<String, Integer> advisorsPerDomain;

        public RegistryStats(int totalAdvisors, int totalDomains,
                             Map<String, Integer> advisorsPerDomain) {
            this.totalAdvisors = totalAdvisors;
            this.totalDomains = totalDomains;
            this.advisorsPerDomain = advisorsPerDomain;
        }

        @Override
        public String toString() {
            return String.format("RegistryStats[advisors=%d, domains=%d]",
                    totalAdvisors, totalDomains);
        }
    }
}
