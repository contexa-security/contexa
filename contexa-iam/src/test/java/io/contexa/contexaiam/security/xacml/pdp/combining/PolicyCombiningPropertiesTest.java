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
package io.contexa.contexaiam.security.xacml.pdp.combining;

import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.BindException;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyCombiningPropertiesTest {

    @Test
    void aUrlNoPolicyNamesNeedsASignedInUserAndAMethodWithoutAPolicyIsPermitted() {
        PolicyCombiningProperties properties = new PolicyCombiningProperties();

        assertThat(properties.getNoMatchingUrlPolicyDecision()).isEqualTo(NoPolicyDecision.AUTHENTICATED);
        assertThat(properties.getMissingMethodPolicyDecision()).isEqualTo(NoPolicyDecision.PERMIT);
    }

    @Test
    void theSettingTakesTheThreeDecisionsForUrls() {
        for (String value : new String[]{"PERMIT", "DENY", "AUTHENTICATED", "authenticated"}) {
            PolicyCombiningProperties properties = bind(Map.of("contexa.policy.no-matching-url-policy-decision", value));
            assertThat(properties.getNoMatchingUrlPolicyDecision().name()).isEqualToIgnoringCase(value);
        }
    }

    @Test
    void aDecisionForUrlsNobodyNamedIsTheSignedInDefaultAndNeverNullOrPermit() {
        PolicyCombiningProperties properties = new PolicyCombiningProperties();
        properties.setNoMatchingUrlPolicyDecision(NoPolicyDecision.PERMIT);

        properties.setNoMatchingUrlPolicyDecision(null);

        assertThat(properties.getNoMatchingUrlPolicyDecision()).isEqualTo(NoPolicyDecision.AUTHENTICATED);
        assertThat(bind(Map.of("contexa.policy.no-matching-url-policy-decision", "")).getNoMatchingUrlPolicyDecision())
                .isEqualTo(NoPolicyDecision.AUTHENTICATED);
    }

    @Test
    void theSettingForMethodsStillTakesOnlyPermitAndDeny() {
        assertThat(bind(Map.of("contexa.policy.missing-method-policy-decision", "DENY")).getMissingMethodPolicyDecision())
                .isEqualTo(NoPolicyDecision.DENY);
        assertThatThrownBy(() -> bind(Map.of("contexa.policy.missing-method-policy-decision", "AUTHENTICATED")))
                .isInstanceOf(BindException.class)
                .hasStackTraceContaining("AUTHENTICATED applies to URL requests only");
        assertThatThrownBy(() -> new PolicyCombiningProperties().setMissingMethodPolicyDecision(NoPolicyDecision.AUTHENTICATED))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void onlyASignedInPrincipalIsGrantedByAuthenticated() {
        assertThat(NoPolicyDecision.AUTHENTICATED.isGrantedTo(UsernamePasswordAuthenticationToken.authenticated(
                "alice", null, AuthorityUtils.createAuthorityList("ROLE_USER")))).isTrue();
        assertThat(NoPolicyDecision.AUTHENTICATED.isGrantedTo(new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")))).isFalse();
        assertThat(NoPolicyDecision.AUTHENTICATED.isGrantedTo(null)).isFalse();
        assertThat(NoPolicyDecision.AUTHENTICATED.isGranted()).isFalse();
        assertThat(NoPolicyDecision.PERMIT.isGrantedTo(null)).isTrue();
        assertThat(NoPolicyDecision.DENY.isGrantedTo(UsernamePasswordAuthenticationToken.authenticated(
                "alice", null, AuthorityUtils.createAuthorityList("ROLE_USER")))).isFalse();
    }

    private static PolicyCombiningProperties bind(Map<String, String> settings) {
        return new Binder(new MapConfigurationPropertySource(settings))
                .bindOrCreate("contexa.policy", Bindable.of(PolicyCombiningProperties.class));
    }
}
