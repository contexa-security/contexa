package io.contexa.autoconfigure.enterprise.dashboard;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.repository.SoarIncidentRepository;
import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.UserTrustMetrics;
import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.HCADFeedbackLoopMetrics;
import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.EventPublishingMetrics;
import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.DefaultRoutingDecisionMetrics;
import io.contexa.contexacoreenterprise.dashboard.metrics.vectorstore.VectorStoreMetricsImpl;
import io.contexa.contexacoreenterprise.dashboard.metrics.unified.UnifiedSecurityMetricsCollector;
import io.contexa.contexacoreenterprise.dashboard.metrics.unified.SystemMetricsCollector;
import io.contexa.contexacoreenterprise.dashboard.metrics.soar.ToolExecutionMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@ConditionalOnClass(name = "io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.UserTrustMetrics")
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "true", matchIfMissing = false)
@EnableConfigurationProperties(ContexaProperties.class)
public class EnterpriseDashboardAutoConfiguration {

    public EnterpriseDashboardAutoConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.dashboard.metrics", name = "enabled", havingValue = "true", matchIfMissing = true)
    public UserTrustMetrics userTrustMetrics(MeterRegistry registry) {
        return new UserTrustMetrics(registry);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.dashboard.metrics", name = "enabled", havingValue = "true", matchIfMissing = true)
    public HCADFeedbackLoopMetrics hcadFeedbackLoopMetrics(MeterRegistry registry) {
        return new HCADFeedbackLoopMetrics(registry);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.dashboard.metrics", name = "enabled", havingValue = "true", matchIfMissing = true)
    public EventPublishingMetrics eventPublishingMetrics(MeterRegistry registry) {
        return new EventPublishingMetrics(registry);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.dashboard.metrics", name = "enabled", havingValue = "true", matchIfMissing = true)
    public DefaultRoutingDecisionMetrics defaultRoutingDecisionMetrics(MeterRegistry registry) {
        return new DefaultRoutingDecisionMetrics(registry);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.dashboard.metrics", name = "enabled", havingValue = "true", matchIfMissing = true)
    public VectorStoreMetricsImpl vectorStoreMetrics() {
        return new VectorStoreMetricsImpl();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.dashboard.metrics", name = "enabled", havingValue = "true", matchIfMissing = true)
    public UnifiedSecurityMetricsCollector unifiedSecurityMetricsCollector(MeterRegistry registry) {
        return new UnifiedSecurityMetricsCollector(registry);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.dashboard.metrics", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SystemMetricsCollector systemMetricsCollector(
            SoarIncidentRepository incidentRepository,
            @Autowired(required = false) MeterRegistry registry) {
        return new SystemMetricsCollector(incidentRepository, registry);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "contexa.dashboard.metrics", name = "enabled", havingValue = "true", matchIfMissing = true)
    public ToolExecutionMetrics toolExecutionMetrics(MeterRegistry registry) {
        return new ToolExecutionMetrics(registry);
    }

}
