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
package io.contexa.contexacommon.properties;

import io.contexa.contexacommon.enums.*;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.Arrays;
import java.util.Set;

@Data
@ConfigurationProperties(prefix = "contexa.auth")
public class AuthContextProperties {

    private StateType stateType = StateType.OAUTH2;

    private OAuth2ServerMode oauth2ServerMode = OAuth2ServerMode.COMBINED;

    private TokenTransportType tokenTransportType = TokenTransportType.HEADER;

    private TokenIssuer tokenIssuer = TokenIssuer.INTERNAL;

    private FactorSelectionType factorSelectionType = FactorSelectionType.SELECT;

    @NestedConfigurationProperty
    private AuthUrlConfig urls = new AuthUrlConfig();

    @NestedConfigurationProperty
    private MfaSettings mfa = new MfaSettings();

    @NestedConfigurationProperty
    private OttSettings ott = new OttSettings();

    @NestedConfigurationProperty
    private JwtsTokenSettings internal = new JwtsTokenSettings();

    @NestedConfigurationProperty
    private OAuth2TokenSettings oauth2 = new OAuth2TokenSettings();

    private long accessTokenValidity = 3600000;       
    private long refreshTokenValidity = 604800000;    
    private long refreshRotateThreshold = 43200000; 

    private boolean enableRefreshToken = true;
    private boolean allowMultipleLogins = false;
    private int maxConcurrentLogins = 3;
    private boolean cookieSecure = true;
    private String cookieSameSite = "Lax";

    private String tokenPersistence = "memory";

    private String tokenPrefix = "Bearer ";
    private String rolesClaim = "roles";
    private String scopesClaim = "scopes";
    private boolean oauth2Csrf = false;

    @Data
    public static class OttSettings {
        private boolean failOnEmailError = true;

        /**
         * Whether a one-time code is written to the log as well as mailed, so that a sign-in finishes without a mail server
         * during development and tests; a mail that fails is then no failed sign-in. Unset, it is on when a profile named
         * local, dev, development or test is active or no mail server is configured, and off otherwise: a production start
         * mails the code only.
         */
        private Boolean codeToConsole;

        /** The profiles of development and tests, in which a one-time code goes to the log as well. */
        public static final Set<String> DEVELOPMENT_PROFILES = Set.of("local", "dev", "development", "test");

        /**
         * Whether one-time codes go to the log too: as configured, or else in development and tests (one of
         * {@link #DEVELOPMENT_PROFILES} active) and wherever no mail server is configured, which could deliver none.
         */
        public boolean writesCodesToConsole(String[] activeProfiles, boolean mailConfigured) {
            if (codeToConsole != null) {
                return codeToConsole;
            }
            return !mailConfigured || Arrays.stream(activeProfiles).anyMatch(DEVELOPMENT_PROFILES::contains);
        }

        /**
         * The mails of a sign-in being sent at one time, each by a thread of Contexa's own, and so the most threads a mail
         * server that does not answer can hold. The request that asked for a mail waits for it no longer than
         * {@code emailSendWaitSeconds}.
         */
        private int emailMaxConcurrentSends = 64;

        /** The seconds a request waits for its mail before it fails as an undelivered mail does; below one it is one. */
        private int emailSendWaitSeconds = 5;

        /**
         * The limit in seconds of the connect, the read and the write of the SMTP conversation. Zero, the default, sets
         * none: the mail of a sign-in goes out with the application's own mail settings, as its other mail does. A value
         * is written into the application's mail sender where its settings
         * ({@code spring.mail.properties.mail.smtp.*timeout}) name none, so it bounds every other mail sent with that
         * sender as well, and a mail server that takes longer to answer then fails the mail.
         */
        private int emailSmtpTimeoutSeconds = 0;
    }

}
