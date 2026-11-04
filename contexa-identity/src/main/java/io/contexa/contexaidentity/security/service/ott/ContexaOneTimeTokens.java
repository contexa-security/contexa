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
package io.contexa.contexaidentity.security.service.ott;

import org.springframework.beans.factory.DisposableBean;

/**
 * The one-time token service of Contexa's own flows (its MFA e-mail codes), held in a bean that is <em>not</em> a
 * {@code OneTimeTokenService}. Spring Security's one-time token login of the application takes its service by type
 * ({@code getBeanProvider(OneTimeTokenService.class).getIfUnique(...)}), and a bean of that type that is the only one is found even when it
 * is not an autowire candidate: the code of the application's login would be generated, stored and mailed by Contexa (its table, its sender).
 * Contexa's flows reach the service by this bean's name.
 */
public final class ContexaOneTimeTokens implements DisposableBean {

    public static final String BEAN_NAME = "contexaOneTimeTokenService";

    private final EmailOneTimeTokenService service;

    public ContexaOneTimeTokens(EmailOneTimeTokenService service) {
        this.service = service;
    }

    public EmailOneTimeTokenService service() {
        return service;
    }

    @Override
    public void destroy() throws Exception {
        service.destroy();
    }
}
