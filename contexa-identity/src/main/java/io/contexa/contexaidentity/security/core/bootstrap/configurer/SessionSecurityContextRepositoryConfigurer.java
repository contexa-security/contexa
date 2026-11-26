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
package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.adapter.auth.ContexaSignInRealm;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import org.springframework.security.web.context.SecurityContextRepository;

public class SessionSecurityContextRepositoryConfigurer implements SecurityConfigurer {

    private static final int ORDER = SecurityConfigurer.HIGHEST_PRECEDENCE + 105;

    private final AISessionSecurityContextRepository aiSessionSecurityContextRepository;
    private final AISessionSecurityContextRepository adminSessionSecurityContextRepository;

    public SessionSecurityContextRepositoryConfigurer(
            AISessionSecurityContextRepository aiSessionSecurityContextRepository) {
        this(aiSessionSecurityContextRepository, null);
    }

    /**
     * @param adminSessionSecurityContextRepository the repository of the flow of Contexa's administrators, which keeps its
     *                                              context under a key of its own; without it that flow takes the other
     */
    public SessionSecurityContextRepositoryConfigurer(
            AISessionSecurityContextRepository aiSessionSecurityContextRepository,
            AISessionSecurityContextRepository adminSessionSecurityContextRepository) {
        this.aiSessionSecurityContextRepository = aiSessionSecurityContextRepository;
        this.adminSessionSecurityContextRepository = adminSessionSecurityContextRepository;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        AISessionSecurityContextRepository repository = ContexaSignInRealm.isAdminFlow(fc.flow()) && adminSessionSecurityContextRepository != null
                ? adminSessionSecurityContextRepository
                : aiSessionSecurityContextRepository;
        if (repository == null) {
            return;
        }
        fc.http().securityContext(sc -> sc.securityContextRepository(repository));
        fc.http().setSharedObject(SecurityContextRepository.class, repository);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
