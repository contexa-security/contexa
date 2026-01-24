package io.contexa.autoconfigure.core.advisor;

import io.contexa.autoconfigure.core.infra.CoreInfrastructureAutoConfiguration;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.advisor.core.BaseAdvisor;
import io.contexa.contexacore.std.advisor.soar.EnhancedSoarApprovalAdvisor;
import io.opentelemetry.api.trace.Tracer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.api.Advisor;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import io.contexa.contexacore.properties.ContexaAdvisorProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;

import jakarta.annotation.PostConstruct;
import java.util.List;


@Slf4j
@AutoConfiguration
@AutoConfigureAfter(CoreInfrastructureAutoConfiguration.class)
@ConditionalOnProperty(
    prefix = "contexa.advisor",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContexaAdvisorProperties.class)
public class CoreAdvisorAutoConfiguration {

    @Value("${contexa.advisor.chain-profile:STANDARD}")
    private String defaultChainProfile;

    @PostConstruct
    public void init() {}

    @Bean
    @ConditionalOnMissingBean
    public AdvisorRegistry advisorRegistry() {
        return new AdvisorRegistry();
    }

    @Bean
    @Primary
    @ConditionalOnProperty(prefix = "contexa.advisor", name = "enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(ChatClient.Builder.class)
    public ChatClient.Builder advisorEnabledChatClientBuilder(
            ChatModel chatModel,
            List<BaseAdvisor> advisors,
            AdvisorRegistry advisorRegistry) {
        
        advisors.forEach(advisor -> {
            advisorRegistry.register(advisor);
                    });

        List<BaseAdvisor> activeAdvisors = advisorRegistry.getEnabled();
        ChatClient.Builder builder = ChatClient.builder(chatModel);
        if (!activeAdvisors.isEmpty()) {
            builder = builder.defaultAdvisors(activeAdvisors.toArray(new Advisor[0]));
        }

        builder = builder.defaultSystem("""
            You are an AI Security Assistant powered by the contexa unified platform.

            🔗 ADVISOR-ENHANCED ECOSYSTEM:
            You have access to a comprehensive advisor system that provides:
            - Domain-specific policy enforcement (SOAR, IAM, Compliance, Threat)
            - Automated approval workflows for high-risk operations
            - Cross-domain context sharing and coordination
            - Real-time metrics and audit logging

            SECURITY CAPABILITIES:
            - Tool execution with risk-based approval
            - Identity and access management integration
            - Compliance validation and reporting
            - Threat detection and mitigation

            OPERATIONAL APPROACH:
            1. All requests are processed through the advisor chain
            2. High-risk operations require explicit approval
            3. All actions are audited and monitored
            4. Cross-domain policies are enforced consistently
            5. Context is shared across security domains

            This advisor-enhanced system ensures comprehensive security
            and compliance across all operations.
            """);

        return builder;
    }

    @Bean(name = "standardChatClient")
    @ConditionalOnProperty(prefix = "contexa.advisor", name = "standard.enabled", havingValue = "true")
    public ChatClient standardChatClient(ChatModel chatModel, AdvisorRegistry advisorRegistry) {
        List<Advisor> advisors = advisorRegistry.buildChain(AdvisorRegistry.ChainProfile.STANDARD);

        return ChatClient.builder(chatModel)
            .defaultAdvisors(advisors.toArray(new Advisor[0]))
            .build();
    }

    @Bean(name = "securityCriticalChatClient")
    @ConditionalOnProperty(prefix = "contexa.advisor", name = "critical.enabled", havingValue = "true")
    public ChatClient securityCriticalChatClient(ChatModel chatModel, AdvisorRegistry advisorRegistry) {
        List<Advisor> advisors = advisorRegistry.buildChain(AdvisorRegistry.ChainProfile.SECURITY_CRITICAL);

        return ChatClient.builder(chatModel)
            .defaultAdvisors(advisors.toArray(new Advisor[0]))
            .build();
    }

    @Bean
    @ConditionalOnProperty(prefix = "contexa.advisor.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public EnhancedSoarApprovalAdvisor soarApprovalAdvisor(Tracer tracer) {
                return new EnhancedSoarApprovalAdvisor(tracer);
    }

    @EventListener(ContextRefreshedEvent.class)
    public void onApplicationReady(ContextRefreshedEvent event) {
        AdvisorRegistry advisorRegistry = event.getApplicationContext().getBean(AdvisorRegistry.class);
        log.info("Advisor System Ready - Registry Status:");
        log.info("  - Total Advisors: {}", advisorRegistry.getStats().totalAdvisors);
        log.info("  - Active Advisors: {}", advisorRegistry.getEnabled().size());
        log.info("  - Domains: {}", advisorRegistry.getDomains());

        advisorRegistry.getEnabled().forEach(advisor ->
                log.debug("  [OK] {} (domain: {}, order: {})",
                        advisor.getName(), advisor.getDomain(), advisor.getOrder())
        );
    }
}
