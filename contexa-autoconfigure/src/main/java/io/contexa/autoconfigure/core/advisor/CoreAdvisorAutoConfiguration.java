package io.contexa.autoconfigure.core.advisor;

import io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration;
import io.contexa.contexacore.properties.ContexaAdvisorProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.advisor.core.BaseAdvisor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;

import java.util.List;

@Slf4j
@AutoConfiguration
@AutoConfigureAfter(CoreInfrastructureAutoConfiguration.class)
@ConditionalOnProperty(prefix = "contexa.advisor", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(ContexaAdvisorProperties.class)
public class CoreAdvisorAutoConfiguration {

    @Autowired(required = false)
    private List<BaseAdvisor> baseAdvisors;

    @Bean
    @ConditionalOnMissingBean
    public AdvisorRegistry advisorRegistry() {
        AdvisorRegistry advisorRegistry = new AdvisorRegistry();
        baseAdvisors.forEach(advisorRegistry::register);
        return advisorRegistry;
    }

    @EventListener(ContextRefreshedEvent.class)
    public void onApplicationReady(ContextRefreshedEvent event) {
        AdvisorRegistry registry = event.getApplicationContext().getBean(AdvisorRegistry.class);
        log.info("Advisor System Ready - Registry Status:");
        log.info("  - Total Advisors: {}", registry.getStats().totalAdvisors);
        log.info("  - Active Advisors: {}", registry.getEnabled().size());
        log.info("  - Domains: {}", registry.getDomains());

        registry.getEnabled().forEach(advisor -> {
            if (advisor instanceof BaseAdvisor baseAdvisor) {
                log.info("  [OK] {} (domain: {}, order: {})",
                        baseAdvisor.getName(), baseAdvisor.getDomain(), baseAdvisor.getOrder());
            } else {
                log.info("  [OK] {} (order: {})", advisor.getName(), advisor.getOrder());
            }
        });
    }
}
