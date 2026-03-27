package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiam.admin.web.auth.controller.IpManagementController;
import io.contexa.contexaiam.admin.web.auth.filter.IpAccessFilter;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.repository.IpAccessRuleRepository;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAdminIpAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public IpAccessRuleService ipAccessRuleService(IpAccessRuleRepository ipAccessRuleRepository) {
        return new IpAccessRuleService(ipAccessRuleRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public IpManagementController ipManagementController(IpAccessRuleService ipAccessRuleService,
                                                          MessageSource messageSource,
                                                          CsvExportService csvExportService) {
        return new IpManagementController(ipAccessRuleService, messageSource, csvExportService);
    }

    @Bean
    @ConditionalOnMissingBean(IpAccessFilter.class)
    public FilterRegistrationBean<IpAccessFilter> ipAccessFilter(IpAccessRuleService ipAccessRuleService) {
        FilterRegistrationBean<IpAccessFilter> reg = new FilterRegistrationBean<>();
        reg.setFilter(new IpAccessFilter(ipAccessRuleService));
        reg.addUrlPatterns("/*");
        reg.setName("ipAccessFilter");
        reg.setOrder(50);
        return reg;
    }
}
