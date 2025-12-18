package io.contexa.autoconfigure.iam.xacml;

import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.prp.DatabasePolicyRetrievalPoint;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * XACML PRP (Policy Retrieval Point) AutoConfiguration
 *
 * ContexaCacheService를 통한 2-Level 캐시를 사용하는
 * DatabasePolicyRetrievalPoint를 자동 등록합니다.
 *
 * @since 0.1.0-ALPHA
 */
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
