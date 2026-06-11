/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
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
