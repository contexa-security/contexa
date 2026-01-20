package io.contexa.autoconfigure.iam.xacml;

import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.prp.DatabasePolicyRetrievalPoint;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;


@AutoConfiguration
public class IamXacmlPrpAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public DatabasePolicyRetrievalPoint databasePolicyRetrievalPoint(
            PolicyRepository policyRepository,
            ContexaCacheService cacheService) {
        return new DatabasePolicyRetrievalPoint(policyRepository, cacheService);
    }
}
