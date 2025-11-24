package io.contexa.autoconfigure.iam.xacml;

import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.BusinessResourceActionRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.security.xacml.pip.attribute.DatabaseAttributePIP;
import io.contexa.contexaiam.security.xacml.pip.context.DefaultContextHandler;
import io.contexa.contexaiam.security.xacml.pip.resolver.GroupAuthorityResolver;
import io.contexa.contexaiam.security.xacml.pip.resolver.RoleAuthorityResolver;
import io.contexa.contexaiam.security.xacml.pip.resolver.UserAuthorityResolver;
import io.contexa.contexaiam.security.xacml.pip.risk.DefaultRiskEngine;
import io.contexa.contexaiam.security.xacml.pip.risk.IpRiskEvaluator;
import io.contexa.contexaiam.security.xacml.pip.risk.RiskFactorEvaluator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

import java.util.List;

/**
 * XACML PIP (Policy Information Point) AutoConfiguration
 */
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
    public GroupAuthorityResolver groupAuthorityResolver(GroupRepository groupRepository) {
        return new GroupAuthorityResolver(groupRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleAuthorityResolver roleAuthorityResolver(RoleRepository roleRepository) {
        return new RoleAuthorityResolver(roleRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public UserAuthorityResolver userAuthorityResolver(UserRepository userRepository) {
        return new UserAuthorityResolver(userRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultContextHandler defaultContextHandler(UserRepository userRepository) {
        return new DefaultContextHandler(userRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public IpRiskEvaluator ipRiskEvaluator() {
        return new IpRiskEvaluator();
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultRiskEngine defaultRiskEngine(List<RiskFactorEvaluator> evaluators) {
        return new DefaultRiskEngine(evaluators);
    }
}
