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
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.repository.PolicyRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The policies a role or a permission is named in, as the console lists them before the role or permission is deleted:
 * a policy is listed when a literal of one of its conditions is the name itself, not when the name is a part of some
 * longer text.
 */
@DataJpaTest(properties = {
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.flyway.enabled=false",
        "spring.liquibase.enabled=false"
})
class PolicyReferencesTest {

    @Autowired
    private PolicyRepository policies;

    @Autowired
    private EntityManager entityManager;

    @BeforeEach
    void policiesAskingForSimilarNames() {
        save("plain", true, "hasAuthority('ROLE_M41_PLAIN')");
        save("oneil-by-authority", true, "hasAuthority('ROLE_O''NEIL') and (hasAuthority('READ'))");
        save("o-by-authority", true, "hasAuthority('ROLE_O') and (hasAuthority('READ'))");
        save("o-in-a-list", true, "hasAnyAuthority('X','ROLE_O')");
        save("o-inactive", false, "hasAuthority('ROLE_O')");
        save("other", true, "hasAuthority('ROLE_OTHER')");
        save("oneil-raw", true, "hasAuthority('O''Neil')");
        save("oneil-with-prefix", true, "hasAuthority('ROLE_O''Neil')");
        save("underscore", true, "hasAuthority('R_D')");
        save("underscore-lookalike", true, "hasAuthority('RAD')");
        save("percent", true, "hasAuthority('100%')");
        save("percent-lookalike", true, "hasAuthority('1000')");
        save("two-rules", true, "hasAuthority('ROLE_TWICE')", "hasAuthority('ROLE_TWICE') and (hasAuthority('READ'))");
        entityManager.flush();
        entityManager.clear();
    }

    private void save(String name, boolean active, String... conditions) {
        Policy policy = Policy.builder().name(name).effect(Policy.Effect.ALLOW).isActive(active).build();
        for (String expression : conditions) {
            PolicyRule rule = PolicyRule.builder().build();
            rule.addCondition(PolicyCondition.builder().expression(expression).build());
            policy.addRule(rule);
        }
        policies.save(policy);
    }

    private List<String> referencing(String... names) {
        return policies.findActivePoliciesReferencing(List.of(names)).stream()
                .map(Policy::getName).sorted().toList();
    }

    @Test
    @DisplayName("several names are the union of what each is named in, each policy once")
    void severalNamesAreTheUnion() {
        assertThat(referencing("ROLE_O'NEIL", "O'Neil")).containsExactly("oneil-by-authority", "oneil-raw");
        assertThat(referencing("ROLE_O", "ROLE_O")).containsExactly("o-by-authority", "o-in-a-list");
        assertThat(referencing()).isEmpty();
    }

    @Test
    @DisplayName("a name is found as a whole literal, not as a part of a longer one")
    void aNameIsFoundAsAWholeLiteral() {
        assertThat(referencing("ROLE_O")).containsExactly("o-by-authority", "o-in-a-list");
        assertThat(referencing("O")).isEmpty();
        assertThat(referencing("ROLE_M41_PLAIN")).containsExactly("plain");
    }

    @Test
    @DisplayName("a name with a quote is found as the literal that doubles it, and only that")
    void aNameWithAQuoteIsFoundAsItsLiteral() {
        assertThat(referencing("ROLE_O'NEIL")).containsExactly("oneil-by-authority");
        assertThat(referencing("O'Neil")).containsExactly("oneil-raw");
        assertThat(referencing("ROLE_O'Neil")).containsExactly("oneil-with-prefix");
    }

    @Test
    @DisplayName("the wildcards of a search are plain characters of the name")
    void wildcardsArePlainCharacters() {
        assertThat(referencing("R_D")).containsExactly("underscore");
        assertThat(referencing("100%")).containsExactly("percent");
    }

    @Test
    @DisplayName("a policy that names it in two rules is listed once, and an inactive policy is not listed")
    void aPolicyIsListedOnce() {
        assertThat(referencing("ROLE_TWICE")).containsExactly("two-rules");
        assertThat(referencing("ROLE_O")).doesNotContain("o-inactive");
    }

    @SpringBootConfiguration
    @EntityScan(basePackageClasses = {Users.class, Policy.class})
    @EnableJpaRepositories(basePackageClasses = PolicyRepository.class,
            includeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = PolicyRepository.class))
    static class Persistence {
    }
}
