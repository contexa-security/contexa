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
import io.contexa.contexacore.autonomous.agent.AgentNoticeChannel;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;

import java.util.Optional;

/**
 * Mails a notice to the person accountable for an agent (docs/agent A5-2, A5-3) through the application's mail sender,
 * to the address the person's account names. Without a mail sender or an address the notice stays for the console.
 */
@Slf4j
public class MailAgentNoticeChannel implements AgentNoticeChannel {

    /** The name a delivered notice is kept with. */
    public static final String MAIL = "MAIL";

    private final EmailService emailService;
    private final UserRepository users;

    public MailAgentNoticeChannel(EmailService emailService, UserRepository users) {
        this.emailService = emailService;
        this.users = users;
    }

    @Override
    public String deliver(AgentNotice notice) {
        if (emailService == null || !emailService.isMailSenderConfigured() || users == null) {
            return null;
        }
        Optional<String> address = users.findByUsername(notice.recipientId())
                .map(Users::getEmail)
                .filter(StringUtils::hasText);
        if (address.isEmpty()) {
            return null;
        }
        StringBuilder body = new StringBuilder()
                .append("<p>").append(HtmlUtils.htmlEscape(notice.message())).append("</p>");
        if (StringUtils.hasText(notice.link())) {
            body.append("<p><a href=\"").append(HtmlUtils.htmlEscape(notice.link())).append("\">")
                    .append(HtmlUtils.htmlEscape(notice.link())).append("</a></p>");
        }
        emailService.sendHtmlMessage(address.get(), notice.subject(), body.toString());
        return MAIL;
    }
}
