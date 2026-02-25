package io.contexa.contexaiam.service;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
public class PolicyService {

    private final PolicyRepository policyRepository;

    @Transactional(readOnly = true)
    public Policy findById(Long id) {
        return policyRepository.findById(id).orElse(null);
    }

    @Transactional
    public Policy save(Policy policy) {
        return policyRepository.save(policy);
    }
}