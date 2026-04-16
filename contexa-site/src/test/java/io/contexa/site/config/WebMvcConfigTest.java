package io.contexa.site.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(WebMvcConfig.class)
class WebMvcConfigTest {

    @Autowired
    private MessageSource messageSource;

    @Test
    void resolvesSiteMessages() {
        assertThat(messageSource.getMessage("site.nav.benchmark", null, Locale.ENGLISH)).isNotBlank();
    }

    @Test
    void resolvesEnterpriseAndBaseMessages() {
        assertThat(messageSource.getMessage("enterprise.saas.clients.title", null, Locale.ENGLISH))
                .isEqualTo("Tenant Service Client Credentials");
        assertThat(messageSource.getMessage("header.home", null, Locale.ENGLISH)).isEqualTo("Home");
    }
}
