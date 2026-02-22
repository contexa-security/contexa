package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiamenterprise.admin.monitor.controller.MetricsDashboardController;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "true", matchIfMissing = false)
@ComponentScan(basePackages = "io.contexa.contexaiamenterprise")
public class IamEnterpriseAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public MetricsDashboardController metricsDashboardController(){
        return new MetricsDashboardController();
    }
}
