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
package io.contexa.autoconfigure.iam;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import jakarta.persistence.EntityManager;
import org.hibernate.Hibernate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * PR-4: the console's policy list on the real queries. A page fetched together with each policy's targets made Hibernate
 * read every policy into memory and cut the page there, with a warning at each opening of the list.
 */
@DataJpaTest(properties = {
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.flyway.enabled=false",
        "spring.liquibase.enabled=false"
})
@ExtendWith(OutputCaptureExtension.class)
class PolicySearchPagingTest {

    private static final Pageable SECOND_PAGE_OF_TWO = PageRequest.of(1, 2, Sort.by(Sort.Direction.DESC, "id"));

    @Autowired
    private PolicyRepository policies;

    @Autowired
    private EntityManager entityManager;

    @BeforeEach
    void fivePolicies() {
        for (int number = 1; number <= 5; number++) {
            Policy policy = Policy.builder().name("policy-" + number).effect(Policy.Effect.ALLOW).build();
            policy.addTarget(PolicyTarget.builder().targetType("URL").targetIdentifier("/a/" + number).build());
            policy.addTarget(PolicyTarget.builder().targetType("URL").targetIdentifier("/b/" + number).build());
            policies.save(policy);
        }
        entityManager.flush();
        entityManager.clear();
    }

    private static List<String> names(Page<Policy> page) {
        return page.getContent().stream().map(Policy::getName).toList();
    }

    @Test
    @DisplayName("a page of the keyword search is read as a page, with the targets of its policies")
    void theKeywordSearchReadsAPage(CapturedOutput output) {
        Page<Policy> page = policies.searchByKeyword("%policy%", SECOND_PAGE_OF_TWO);

        assertThat(names(page)).containsExactly("policy-3", "policy-2");
        assertThat(page.getTotalElements()).isEqualTo(5);
        assertThat(page.getTotalPages()).isEqualTo(3);
        assertThat(page.getContent()).allSatisfy(policy -> {
            assertThat(Hibernate.isInitialized(policy.getTargets())).isTrue();
            assertThat(policy.getTargets()).hasSize(2);
        });
        assertThat(output).doesNotContain("HHH90003004");
    }

    @Test
    @DisplayName("a page of the filtered search is read as a page, with the targets of its policies")
    void theFilteredSearchReadsAPage(CapturedOutput output) {
        Page<Policy> page = policies.searchByFilters("%policy%", Policy.ApprovalStatus.PENDING, false, SECOND_PAGE_OF_TWO);

        assertThat(names(page)).containsExactly("policy-3", "policy-2");
        assertThat(page.getTotalElements()).isEqualTo(5);
        assertThat(page.getContent()).allSatisfy(policy -> assertThat(policy.getTargets()).hasSize(2));
        assertThat(output).doesNotContain("HHH90003004");
    }

    @Test
    @DisplayName("a search that finds nothing is an empty page")
    void aSearchThatFindsNothingIsAnEmptyPage() {
        Page<Policy> page = policies.searchByKeyword("%nothing%", PageRequest.of(0, 2));

        assertThat(page.getContent()).isEmpty();
        assertThat(page.getTotalElements()).isZero();
    }

    @SpringBootConfiguration
    @EntityScan(basePackageClasses = {Users.class, Policy.class})
    @EnableJpaRepositories(basePackageClasses = PolicyRepository.class,
            includeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = PolicyRepository.class))
    static class Persistence {
    }
}
