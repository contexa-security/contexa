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
            BusinessResourceActionRepository resourceActionRepository,
            io.contexa.contexacommon.cache.ContexaCacheService cacheService) {
        return new DatabaseAttributePIP(userRepository, auditLogRepository, resourceActionRepository, cacheService);
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultContextHandler defaultContextHandler(
            UserRepository userRepository,
            io.contexa.contexacommon.cache.ContexaCacheService cacheService) {
        return new DefaultContextHandler(userRepository, cacheService);
    }
}
