package io.contexa.contexaiam.properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("IamAdminProperties binding")
class IamAdminPropertiesBindingTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(Config.class);

    @Test
    @DisplayName("condition-templates.enabled defaults to false when no property is provided")
    void conditionTemplatesEnabled_defaultsToFalse() {
        contextRunner.run(context -> {
            IamAdminProperties properties = context.getBean(IamAdminProperties.class);

            assertThat(properties.getConditionTemplates()).isNotNull();
            assertThat(properties.getConditionTemplates().isEnabled())
                    .as("condition-templates must be opt-in; default must be false")
                    .isFalse();
        });
    }

    @Test
    @DisplayName("condition-templates.enabled=true binds via YAML kebab-case property")
    void conditionTemplatesEnabled_true_bindsCorrectly() {
        contextRunner
                .withPropertyValues("contexa.iam.admin.condition-templates.enabled=true")
                .run(context -> {
                    IamAdminProperties properties = context.getBean(IamAdminProperties.class);
                    assertThat(properties.getConditionTemplates().isEnabled()).isTrue();
                });
    }

    @Test
    @DisplayName("condition-templates.enabled=false binds explicitly")
    void conditionTemplatesEnabled_false_bindsCorrectly() {
        contextRunner
                .withPropertyValues("contexa.iam.admin.condition-templates.enabled=false")
                .run(context -> {
                    IamAdminProperties properties = context.getBean(IamAdminProperties.class);
                    assertThat(properties.getConditionTemplates().isEnabled()).isFalse();
                });
    }

    @EnableConfigurationProperties(IamAdminProperties.class)
    static class Config {
    }
}
