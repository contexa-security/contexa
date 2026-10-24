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
package io.contexa.contexaidentity.security.agent;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.agent.AgentNotice;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * docs/agent A5-3, A5-2: a notice reaches the person by mail through the application's mail sender, escaped; without a
 * mail sender or an address it is kept for the console only.
 */
class MailAgentNoticeChannelTest {

    private final EmailService email = mock(EmailService.class);
    private final UserRepository users = mock(UserRepository.class);
    private final MailAgentNoticeChannel channel = new MailAgentNoticeChannel(email, users);

    @Test
    void aNoticeIsMailedToThePersonsAddressEscaped() {
        when(email.isMailSenderConfigured()).thenReturn(true);
        when(users.findByUsername("alice")).thenReturn(Optional.of(Users.builder().username("alice")
                .email("alice@example.test").build()));

        assertThat(channel.deliver(notice("alice", "Stopped: <script>x</script>", "https://console.test/n?a=1&b=2")))
                .isEqualTo(MailAgentNoticeChannel.MAIL);

        verify(email).sendHtmlMessage("alice@example.test", "The agent report-agent was stopped",
                "<p>Stopped: &lt;script&gt;x&lt;/script&gt;</p>"
                        + "<p><a href=\"https://console.test/n?a=1&amp;b=2\">https://console.test/n?a=1&amp;b=2</a></p>");
    }

    @Test
    void withoutAMailSenderOrAnAddressTheNoticeIsNotMailed() {
        when(email.isMailSenderConfigured()).thenReturn(false);
        assertThat(channel.deliver(notice("alice", "Stopped", null))).isNull();

        when(email.isMailSenderConfigured()).thenReturn(true);
        when(users.findByUsername("bob")).thenReturn(Optional.of(Users.builder().username("bob").build()));
        when(users.findByUsername("ghost")).thenReturn(Optional.empty());
        assertThat(channel.deliver(notice("bob", "Stopped", null))).isNull();
        assertThat(channel.deliver(notice("ghost", "Stopped", null))).isNull();

        verify(email, never()).sendHtmlMessage(anyString(), anyString(), anyString());
    }

    private static AgentNotice notice(String recipient, String message, String link) {
        return new AgentNotice("n-1", AgentNotice.AGENT_STOPPED, null, recipient, "report-agent", null,
                "The agent report-agent was stopped", message, link, null, Instant.parse("2026-10-24T01:00:00Z"),
                AgentNotice.CONSOLE, null);
    }
}
