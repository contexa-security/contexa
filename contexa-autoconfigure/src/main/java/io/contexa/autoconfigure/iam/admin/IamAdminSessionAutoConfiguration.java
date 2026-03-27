package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiam.admin.web.auth.controller.SessionManagementController;
import io.contexa.contexaiam.admin.web.auth.filter.SessionTrackingFilter;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAdminSessionAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SessionManagementService sessionManagementService(
            ActiveSessionRepository activeSessionRepository) {
        return new SessionManagementService(activeSessionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionManagementController sessionManagementController(
            SessionManagementService sessionManagementService,
            MessageSource messageSource,
            CsvExportService csvExportService) {
        return new SessionManagementController(sessionManagementService, messageSource, csvExportService);
    }

    @Bean
    @ConditionalOnMissingBean(SessionTrackingFilter.class)
    public FilterRegistrationBean<SessionTrackingFilter> sessionTrackingFilter(
            SessionManagementService sessionManagementService) {
        FilterRegistrationBean<SessionTrackingFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new SessionTrackingFilter(sessionManagementService));
        registration.addUrlPatterns("/*");
        registration.setName("sessionTrackingFilter");
        registration.setOrder(200);
        return registration;
    }
}
