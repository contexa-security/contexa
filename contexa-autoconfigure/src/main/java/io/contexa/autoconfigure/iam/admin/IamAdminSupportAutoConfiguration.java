package io.contexa.autoconfigure.iam.admin;

import io.contexa.contexaiam.admin.support.translation.TerminologyTranslationService;
import io.contexa.contexaiam.admin.support.translation.TerminologyTranslationServiceImpl;
import io.contexa.contexaiam.admin.support.visualization.service.VisualizationService;
import io.contexa.contexaiam.admin.support.visualization.service.VisualizationServiceImpl;
import io.contexa.contexaiam.security.xacml.pdp.translator.PolicyTranslator;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class IamAdminSupportAutoConfiguration {

    // Services (2개)
    @Bean
    @ConditionalOnMissingBean
    public VisualizationService visualizationService(UserRepository userRepository) {
        return new VisualizationServiceImpl(userRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public TerminologyTranslationService terminologyTranslationService(
            PermissionRepository permissionRepository,
            PolicyTranslator policyTranslator) {
        return new TerminologyTranslationServiceImpl(permissionRepository, policyTranslator);
    }
}
