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

import io.contexa.autoconfigure.ai.ContexaServletFilterOrder;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexaiam.admin.web.auth.controller.IpManagementController;
import io.contexa.contexaiam.admin.web.auth.filter.IpAccessFilter;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.properties.IamAdminProperties;
import io.contexa.contexaiam.repository.IpAccessRuleRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties({TieredStrategyProperties.class, IamAdminProperties.class})
public class IamAdminIpAutoConfiguration {

    @Bean(name = "contexaIpAccessRuleService")
    @ConditionalOnMissingBean
    public IpAccessRuleService ipAccessRuleService(IpAccessRuleRepository ipAccessRuleRepository,
                                                   ObjectProvider<CentralAuditFacade> centralAuditFacade) {
        IpAccessRuleService service = new IpAccessRuleService(ipAccessRuleRepository);
        // K130: a change of the rules is audited
        centralAuditFacade.ifAvailable(service::setCentralAuditFacade);
        return service;
    }

    @Bean(name = "contexaIpManagementController")
    @ConditionalOnMissingBean
    public IpManagementController ipManagementController(IpAccessRuleService contexaIpAccessRuleService,
                                                          MessageSource messageSource,
                                                          CsvExportService contexaCsvExportService,
                                                          TieredStrategyProperties tieredStrategyProperties) {
        // The change is checked against the address the IP access filter reads, with the proxies it trusts.
        return new IpManagementController(contexaIpAccessRuleService, messageSource, contexaCsvExportService,
                tieredStrategyProperties.getSecurity());
    }

    /**
     * The address control (M4 of docs/agent/운영모드-정상화-구현계획.md): on the paths its setting names, every path by
     * default, whatever the mode and the ownership; ahead of the Spring Security filter chain, so that an address its rules
     * shut out reaches no chain. Without rules it lets every request through as it came.
     */
    @Bean(name = "contexaIpAccessFilter")
    @ConditionalOnMissingBean(IpAccessFilter.class)
    public FilterRegistrationBean<IpAccessFilter> ipAccessFilter(IpAccessRuleService contexaIpAccessRuleService,
                                                                 TieredStrategyProperties tieredStrategyProperties,
                                                                 IamAdminProperties iamAdminProperties,
                                                                 ObjectProvider<SecurityProperties> securityProperties) {
        FilterRegistrationBean<IpAccessFilter> reg = new FilterRegistrationBean<>();
        reg.setFilter(new IpAccessFilter(contexaIpAccessRuleService, tieredStrategyProperties.getSecurity()));
        reg.setUrlPatterns(iamAdminProperties.getIpAccess().getUrlPatterns());
        reg.setName("contexaIpAccessFilter");
        reg.setOrder(ContexaServletFilterOrder.securityFilterOrder(securityProperties) + ContexaServletFilterOrder.ADDRESS_CONTROL);
        return reg;
    }
}

