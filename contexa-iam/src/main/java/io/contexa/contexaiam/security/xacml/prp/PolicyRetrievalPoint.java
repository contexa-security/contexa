package io.contexa.contexaiam.security.xacml.prp;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;

import java.util.List;

public interface PolicyRetrievalPoint {

    @Cacheable(value = "urlPolicies", key = "'allUrlPolicies'")
    List<Policy> findUrlPolicies();

    @CacheEvict(value = "urlPolicies", allEntries = true)
    void clearUrlPoliciesCache();

    @Cacheable(value = "methodPolicies", key = "#methodIdentifier")
    List<Policy> findMethodPolicies(String methodIdentifier);

    @CacheEvict(value = "methodPolicies", allEntries = true)
    void clearMethodPoliciesCache();

    List<Policy> findMethodPolicies(String methodIdentifier, String phase);
}