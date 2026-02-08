package io.contexa.contexaiam.security.xacml.prp;

import com.fasterxml.jackson.core.type.TypeReference;
import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class DatabasePolicyRetrievalPoint implements PolicyRetrievalPoint {

    private static final String CACHE_DOMAIN = "policies";
    private static final String URL_POLICIES_KEY = "policies:url:all";
    private static final String METHOD_POLICIES_PREFIX = "policies:method:";

    private static final TypeReference<List<Policy>> POLICY_LIST_TYPE = new TypeReference<>() {
    };

    private final PolicyRepository policyRepository;
    private final ContexaCacheService cacheService;

    @Override
    public List<Policy> findUrlPolicies() {
        return cacheService.get(
                URL_POLICIES_KEY,
                () -> {
                    List<Policy> policies = policyRepository.findByTargetTypeWithDetails("URL");
                    return policies;
                },
                POLICY_LIST_TYPE,
                CACHE_DOMAIN
        );
    }

    @Override
    public void clearUrlPoliciesCache() {
        cacheService.invalidate(URL_POLICIES_KEY);
    }

    @Override
    public List<Policy> findMethodPolicies(String methodIdentifier) {
        String cacheKey = METHOD_POLICIES_PREFIX + methodIdentifier;

        return cacheService.get(
                cacheKey,
                () -> {
                    return policyRepository.findByMethodIdentifier(methodIdentifier);
                },
                POLICY_LIST_TYPE,
                CACHE_DOMAIN
        );
    }

    @Override
    public void clearMethodPoliciesCache() {
        cacheService.invalidate(METHOD_POLICIES_PREFIX + "*");
    }
}
