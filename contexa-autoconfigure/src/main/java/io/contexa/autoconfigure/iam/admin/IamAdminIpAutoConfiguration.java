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

import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexaiam.admin.web.auth.controller.IpManagementController;
import io.contexa.contexaiam.admin.web.auth.filter.IpAccessFilter;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.repository.IpAccessRuleRepository;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties(TieredStrategyProperties.class)
public class IamAdminIpAutoConfiguration {

    @Bean(name = "contexaIpAccessRuleService")
    @ConditionalOnMissingBean
    public IpAccessRuleService ipAccessRuleService(IpAccessRuleRepository ipAccessRuleRepository) {
        return new IpAccessRuleService(ipAccessRuleRepository);
    }

    @Bean(name = "contexaIpManagementController")
    @ConditionalOnMissingBean
    public IpManagementController ipManagementController(IpAccessRuleService contexaIpAccessRuleService,
                                                          MessageSource messageSource,
                                                          CsvExportService contexaCsvExportService) {
        return new IpManagementController(contexaIpAccessRuleService, messageSource, contexaCsvExportService);
    }

    @Bean(name = "contexaIpAccessFilter")
    @ConditionalOnMissingBean(IpAccessFilter.class)
    public FilterRegistrationBean<IpAccessFilter> ipAccessFilter(IpAccessRuleService contexaIpAccessRuleService,
                                                                 TieredStrategyProperties tieredStrategyProperties,
                                                                 BridgeProperties bridgeProperties) {
        FilterRegistrationBean<IpAccessFilter> reg = new FilterRegistrationBean<>();
        reg.setFilter(new IpAccessFilter(contexaIpAccessRuleService, tieredStrategyProperties.getSecurity()));
        reg.addUrlPatterns(bridgeProperties.ownershipBehaviour().adminIpFilterPattern());
        reg.setName("contexaIpAccessFilter");
        reg.setOrder(50);
        return reg;
    }
}

