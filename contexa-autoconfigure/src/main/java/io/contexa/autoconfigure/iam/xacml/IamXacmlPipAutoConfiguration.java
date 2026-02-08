package io.contexa.autoconfigure.iam.xacml;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.security.xacml.pip.attribute.DatabaseAttributePIP;
import io.contexa.contexaiam.security.xacml.pip.context.DefaultContextHandler;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;


@AutoConfiguration
public class IamXacmlPipAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public DatabaseAttributePIP databaseAttributePIP(
            UserRepository userRepository,
            AuditLogRepository auditLogRepository,
            BusinessResourceActionRepository resourceActionRepository) {
        return new DatabaseAttributePIP(userRepository, auditLogRepository, resourceActionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultContextHandler defaultContextHandler(UserRepository userRepository) {
        return new DefaultContextHandler(userRepository);
    }
}
