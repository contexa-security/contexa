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

import io.contexa.contexacore.autonomous.agent.AgentAllowReuse;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent F-1, RL-5: the limits of an ALLOW's reuse are the application's settings
 * ({@code contexa.security.zerotrust.agent.allow-reuse}); a sensitive resource answers one resource by default, and the
 * application may widen that up to the general limit.
 */
class AllowReuseWiringTest {

    private static final String KEY = "alice::agent::agent-7";

    private static AgentAllowReuse reuseOf(SecurityZeroTrustProperties properties) {
        return new CoreAutonomousEventAutoConfiguration().agentAllowReuse(properties);
    }

    @Test
    void byDefaultAnAllowAnswersThreeResourcesButOnlyOneSensitiveResource() {
        AgentAllowReuse reuse = reuseOf(new SecurityZeroTrustProperties());
        reuse.decided(KEY, "context", ActionFamily.READ, "CUS-1");

        assertThat(reuse.answers(KEY, "context", ActionFamily.READ, "CUS-2", true)).isFalse();
        assertThat(reuse.answers(KEY, "context", ActionFamily.READ, "DOC-2", false)).isTrue();
        assertThat(reuse.answers(KEY, "context", ActionFamily.READ, "DOC-3", false)).isTrue();
        assertThat(reuse.answers(KEY, "context", ActionFamily.READ, "DOC-4", false)).isFalse();
    }

    @Test
    void theApplicationMayWidenTheSensitiveLimit() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.getAgent().getAllowReuse().setSensitiveMaxDistinctResources(3);
        AgentAllowReuse reuse = reuseOf(properties);
        reuse.decided(KEY, "context", ActionFamily.READ, "CUS-1");

        assertThat(reuse.answers(KEY, "context", ActionFamily.READ, "CUS-2", true)).isTrue();
        assertThat(reuse.answers(KEY, "context", ActionFamily.READ, "CUS-3", true)).isTrue();
        assertThat(reuse.answers(KEY, "context", ActionFamily.READ, "CUS-4", true)).isFalse();
    }
}
