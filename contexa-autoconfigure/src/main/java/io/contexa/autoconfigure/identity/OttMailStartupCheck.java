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
package io.contexa.autoconfigure.identity;

import io.contexa.contexaidentity.security.service.ott.EmailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Once the application is ready, connects to the mail server of the one-time sign-in codes and says in the log whether it
 * works and, if not, what to set. A wrong mail setting showed only at the first sign-in that needed a code, as a refused
 * code. The check runs on a thread of its own, so a server that does not answer delays nothing.
 */
@Slf4j
public class OttMailStartupCheck implements ApplicationListener<ApplicationReadyEvent> {

    static final String WHAT_TO_SET = "Set SPRING_MAIL_HOST, SPRING_MAIL_PORT, SPRING_MAIL_USERNAME and SPRING_MAIL_PASSWORD "
            + "(with spring.mail.properties.mail.smtp.auth and mail.smtp.starttls.enable as the server asks) to a server that "
            + "works. In development the Mailpit of contexa-local takes mail at 127.0.0.1:51025 without a sign-in and shows it "
            + "at http://127.0.0.1:58025.";

    private final EmailService mail;
    private final boolean codeToConsole;
    private final AtomicBoolean checked = new AtomicBoolean();

    public OttMailStartupCheck(EmailService mail, boolean codeToConsole) {
        this.mail = mail;
        this.codeToConsole = codeToConsole;
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        if (!mail.isMailSenderConfigured() || !checked.compareAndSet(false, true)) {
            return;
        }
        Thread thread = new Thread(this::check, "contexa-mail-check");
        thread.setDaemon(true);
        thread.start();
    }

    void check() {
        String server = mail.serverAddress();
        Exception failure = mail.checkServer();
        if (failure == null) {
            log.info("[Contexa] One-time sign-in codes are mailed through {}", server);
            return;
        }
        log.warn("[Contexa] The mail server of the one-time sign-in codes ({}) did not take the connection: {}. {} {}",
                server, rootCause(failure),
                codeToConsole ? "Codes are written to this log meanwhile, so sign-ins go on."
                        : "Until then a sign-in that needs a mailed code is refused.",
                WHAT_TO_SET);
    }

    private static String rootCause(Throwable failure) {
        Throwable cause = failure;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        return cause.getClass().getSimpleName() + (cause.getMessage() != null ? " (" + cause.getMessage() + ")" : "");
    }
}
