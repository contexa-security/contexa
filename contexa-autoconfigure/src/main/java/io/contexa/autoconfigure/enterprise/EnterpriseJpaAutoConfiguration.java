package io.contexa.autoconfigure.enterprise;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@AutoConfiguration
@ConditionalOnClass(name = {
        "io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository",
        "jakarta.persistence.EntityManager"
})
@ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "true", matchIfMissing = false)
@EnableJpaRepositories(basePackages = {
        "io.contexa.contexacoreenterprise.repository"
})
@EntityScan(basePackages = {
        "io.contexa.contexacoreenterprise.domain.entity"
})
public class EnterpriseJpaAutoConfiguration {

    public EnterpriseJpaAutoConfiguration() {
    }
}
