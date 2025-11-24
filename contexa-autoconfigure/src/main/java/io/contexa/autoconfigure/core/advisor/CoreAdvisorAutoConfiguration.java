package io.contexa.autoconfigure.core.advisor;

import io.contexa.autoconfigure.core.infrastructure.CoreInfrastructureAutoConfiguration;
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

/**
 * Core Advisor AutoConfiguration
 *
 * Contexa 프레임워크의 Advisor 시스템 자동 구성을 제공합니다.
 *
 * 포함된 Bean (5개):
 * - AdvisorRegistry - Advisor 중앙 관리 레지스트리
 * - advisorEnabledChatClientBuilder - Advisor 지원 ChatClient.Builder (@Primary)
 * - standardChatClient - Standard profile ChatClient
 * - securityCriticalChatClient - Security critical profile ChatClient
 * - soarApprovalAdvisor - SOAR 도메인 Advisor
 *
 * 활성화 조건:
 * contexa:
 *   advisor:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
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
    public void init() {
        log.info("Advisor Auto Configuration 시작");
        log.info("  - Default chain profile: {}", defaultChainProfile);
    }

    /**
     * 1. AdvisorRegistry Bean 등록
     * Advisor 중앙 관리 레지스트리
     */
    @Bean
    @ConditionalOnMissingBean
    public AdvisorRegistry advisorRegistry() {
        return new AdvisorRegistry();
    }

    /**
     * 2. ChatClient.Builder Bean with Advisor support
     *
     * Advisor를 지원하는 ChatClient.Builder를 제공합니다.
     * @Primary로 지정하여 기본 Builder로 사용됩니다.
     */
    @Bean
    @Primary
    @ConditionalOnProperty(prefix = "contexa.advisor", name = "enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(ChatClient.Builder.class)
    public ChatClient.Builder advisorEnabledChatClientBuilder(
            ChatModel chatModel,
            List<BaseAdvisor> advisors,
            AdvisorRegistry advisorRegistry) {
        log.info("Advisor-enabled ChatClient.Builder 생성");

        // 주입받은 모든 BaseAdvisor를 Registry에 등록
        advisors.forEach(advisor -> {
            advisorRegistry.register(advisor);
            log.info("Advisor 등록: {} (order: {})", advisor.getName(), advisor.getOrder());
        });

        // 활성화된 모든 Advisor를 가져와서 order 순으로 정렬
        List<BaseAdvisor> activeAdvisors = advisorRegistry.getEnabled();

        log.info("{} 개의 활성 Advisor를 ChatClient에 적용", activeAdvisors.size());
        activeAdvisors.forEach(advisor ->
            log.info("  - {} (order: {})", advisor.getName(), advisor.getOrder())
        );

        ChatClient.Builder builder = ChatClient.builder(chatModel);

        if (!activeAdvisors.isEmpty()) {
            builder = builder.defaultAdvisors(activeAdvisors.toArray(new Advisor[0]));
        }

        // 기본 시스템 프롬프트 설정
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

    /**
     * 3. Standard profile ChatClient
     */
    @Bean(name = "standardChatClient")
    @ConditionalOnProperty(prefix = "contexa.advisor", name = "standard.enabled", havingValue = "true")
    public ChatClient standardChatClient(ChatModel chatModel, AdvisorRegistry advisorRegistry) {
        List<Advisor> advisors = advisorRegistry.buildChain(AdvisorRegistry.ChainProfile.STANDARD);

        return ChatClient.builder(chatModel)
            .defaultAdvisors(advisors.toArray(new Advisor[0]))
            .build();
    }

    /**
     * 4. Security critical profile ChatClient
     */
    @Bean(name = "securityCriticalChatClient")
    @ConditionalOnProperty(prefix = "contexa.advisor", name = "critical.enabled", havingValue = "true")
    public ChatClient securityCriticalChatClient(ChatModel chatModel, AdvisorRegistry advisorRegistry) {
        List<Advisor> advisors = advisorRegistry.buildChain(AdvisorRegistry.ChainProfile.SECURITY_CRITICAL);

        return ChatClient.builder(chatModel)
            .defaultAdvisors(advisors.toArray(new Advisor[0]))
            .build();
    }

    /**
     * 5. SOAR 도메인 Advisor 등록
     */
    @Bean
    @ConditionalOnProperty(prefix = "contexa.advisor.soar", name = "enabled", havingValue = "true", matchIfMissing = true)
    public EnhancedSoarApprovalAdvisor soarApprovalAdvisor(Tracer tracer) {
        log.info("SOAR Approval Advisor Bean 생성");
        return new EnhancedSoarApprovalAdvisor(tracer);
    }

    /**
     * ApplicationContext 초기화 완료 후 Advisor 상태 확인
     * 디버깅 및 모니터링 목적
     */
    @EventListener(ContextRefreshedEvent.class)
    public void onApplicationReady(AdvisorRegistry advisorRegistry) {
        log.info("Advisor System Ready - Registry Status:");
        log.info("  - Total Advisors: {}", advisorRegistry.getStats().totalAdvisors);
        log.info("  - Active Advisors: {}", advisorRegistry.getEnabled().size());
        log.info("  - Domains: {}", advisorRegistry.getDomains());

        advisorRegistry.getEnabled().forEach(advisor ->
            log.debug("  ✓ {} (domain: {}, order: {})",
                advisor.getName(), advisor.getDomain(), advisor.getOrder())
        );
    }
}
