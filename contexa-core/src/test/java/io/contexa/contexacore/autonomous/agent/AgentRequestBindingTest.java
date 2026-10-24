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
package io.contexa.contexacore.autonomous.agent;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** docs/agent A5-9: a confirmation is bound to its one request and to nothing else. */
class AgentRequestBindingTest {

    private static final String BODY = AgentRequestBinding.sha256Hex("{\"ids\":[1,2]}".getBytes(StandardCharsets.UTF_8));

    @Test
    void theSameRequestSentAgainBindsTheSame() {
        String bound = hash("alice", "report-agent", "post", "/api/export", "b=2&a=1", BODY);

        assertThat(hash("alice", "report-agent", "POST", "/api/export", "a=1&b=2", BODY)).isEqualTo(bound);
        assertThat(hash("alice", "report-agent", "POST", "/api/export", "a=%31&b=2", BODY)).isEqualTo(bound);
        assertThat(bound).hasSize(64);
    }

    @Test
    void anyOtherRequestBindsAnother() {
        String bound = hash("alice", "report-agent", "POST", "/api/export", "a=1", BODY);

        assertThat(hash("bob", "report-agent", "POST", "/api/export", "a=1", BODY)).isNotEqualTo(bound);
        assertThat(hash("alice", "other-agent", "POST", "/api/export", "a=1", BODY)).isNotEqualTo(bound);
        assertThat(hash("alice", "report-agent", "PUT", "/api/export", "a=1", BODY)).isNotEqualTo(bound);
        assertThat(hash("alice", "report-agent", "POST", "/api/exports", "a=1", BODY)).isNotEqualTo(bound);
        assertThat(hash("alice", "report-agent", "POST", "/api/export", "a=2", BODY)).isNotEqualTo(bound);
        assertThat(hash("alice", "report-agent", "POST", "/api/export", "a=1", null)).isNotEqualTo(bound);
        assertThat(hash("alice", "report-agent", "POST", "/api/export", "a=1",
                AgentRequestBinding.sha256Hex("{\"ids\":[1,2,3]}".getBytes(StandardCharsets.UTF_8))))
                .isNotEqualTo(bound);
        assertThat(AgentRequestBinding.hash("tenant-acme", "alice", "report-agent", "POST", "/api/export", "a=1",
                BODY, null)).isNotEqualTo(bound);
    }

    @Test
    void aFormPostBindsItsParameters() {
        String form = AgentRequestBinding.hash(null, "alice", "report-agent", "POST", "/api/export", null, null,
                Map.of("b", new String[]{"2"}, "a", new String[]{"1", "0"}));

        assertThat(AgentRequestBinding.hash(null, "alice", "report-agent", "POST", "/api/export", null, null,
                Map.of("a", new String[]{"0", "1"}, "b", new String[]{"2"}))).isEqualTo(form);
        assertThat(AgentRequestBinding.hash(null, "alice", "report-agent", "POST", "/api/export", null, null,
                Map.of("a", new String[]{"1"}, "b", new String[]{"2"}))).isNotEqualTo(form);
    }

    private static String hash(String user, String agent, String method, String path, String query, String body) {
        return AgentRequestBinding.hash(null, user, agent, method, path, query, body, null);
    }
}
