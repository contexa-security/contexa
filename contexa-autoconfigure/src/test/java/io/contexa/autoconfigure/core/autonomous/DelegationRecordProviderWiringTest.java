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
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacore.autonomous.context.enricher.DelegationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.DelegationRecordLookup;
import io.contexa.contexacore.autonomous.context.enricher.RecordedDelegationContextProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Method;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** A1-4: a host's delegation record lookup turns the recorded delegation provider on; without one nothing changes. */
class DelegationRecordProviderWiringTest {

    @Test
    void theProviderIsMadeOnlyWhenTheHostDeclaresALookupAndCanBeReplaced() throws Exception {
        Method method = CoreAutonomousAutoConfiguration.class.getDeclaredMethod(
                "recordedDelegationContextProvider", DelegationRecordLookup.class);

        assertThat(method.getAnnotation(ConditionalOnBean.class).value()).containsExactly(DelegationRecordLookup.class);
        assertThat(method.getAnnotation(ConditionalOnMissingBean.class).value())
                .containsExactly(RecordedDelegationContextProvider.class);
    }

    @Test
    void theProviderUsesTheHostsLookupAndIsADelegationProvider() {
        DelegationRecordLookup lookup = query -> Optional.empty();

        Object provider = new CoreAutonomousAutoConfiguration().recordedDelegationContextProvider(lookup);

        // The canonical context collects every DelegationContextProvider bean in order (canonicalSecurityContextProvider).
        assertThat(provider).isInstanceOf(DelegationContextProvider.class);
        assertThat(ReflectionTestUtils.getField(provider, "lookup")).isSameAs(lookup);
    }
}
