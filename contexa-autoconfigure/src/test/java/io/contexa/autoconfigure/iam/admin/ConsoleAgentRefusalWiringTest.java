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
package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.handler.MappedInterceptor;
import org.springframework.web.util.ServletRequestPathUtils;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The console's refusal of agents is a mapped interceptor bean: every handler mapping picks it up by its type, whatever
 * MVC setup the application has, and it covers every path of the console.
 */
class ConsoleAgentRefusalWiringTest {

    @Test
    void theConsoleRefusesAnAgentOnEveryPathOfIt() throws Exception {
        MappedInterceptor refusal = new IamAdminAuthAutoConfiguration().contexaConsoleAgentRefusal();

        MockHttpServletRequest application = new MockHttpServletRequest("POST", "/api/exports");
        ServletRequestPathUtils.parseAndCache(application);
        assertThat(refusal.matches(application)).isFalse();
        MockHttpServletRequest fromAnAgent = new MockHttpServletRequest("POST", "/contexa/admin/api/agents/stops");
        ServletRequestPathUtils.parseAndCache(fromAnAgent);
        fromAnAgent.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, new DelegationStamp("admin",
                "report-agent", true, null, null, null, List.of(), List.of(), null, null, null, null, Map.of()));
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(refusal.matches(fromAnAgent)).isTrue();
        assertThat(refusal.preHandle(fromAnAgent, response, new Object())).isFalse();
        assertThat(response.getStatus()).isEqualTo(403);
    }
}
