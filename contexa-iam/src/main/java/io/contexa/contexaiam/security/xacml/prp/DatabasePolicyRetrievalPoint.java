package io.contexa.contexaiam.security.xacml.prp;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class DatabasePolicyRetrievalPoint implements PolicyRetrievalPoint {

    private final PolicyRepository policyRepository;

    @Override
    public List<Policy> findUrlPolicies() {
        log.debug("Fetching all URL policies from database...");
        List<Policy> policies = policyRepository.findByTargetTypeWithDetails("URL");
        log.info("Retrieved {} URL policies.", policies.size());
        return policies;
    }

    @Override
    public void clearUrlPoliciesCache() {
        log.info("URL policies cache will be evicted by annotation.");
    }

    @Override
    public List<Policy> findMethodPolicies(String methodIdentifier) {
        log.debug("Fetching method policies for identifier: {}", methodIdentifier);
        return policyRepository.findByMethodIdentifier(methodIdentifier);
    }

    @Override
    public List<Policy> findMethodPolicies(String methodIdentifier, String phase) { // [수정] phase 파라미터 추가
        log.debug("Fetching method policies for identifier: {} and phase: {}", methodIdentifier, phase);
        PolicyCondition.AuthorizationPhase authPhase = PolicyCondition.AuthorizationPhase.valueOf(phase);
        return policyRepository.findByMethodIdentifierAndPhase(methodIdentifier, authPhase); // [수정] 새 쿼리 호출
    }

    @Override
    public void clearMethodPoliciesCache() {
        log.info("Method policies cache will be evicted by annotation.");
    }
}
