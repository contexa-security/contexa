package io.contexa.showcase.portal.lab;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/** The lab's composition and records (docs/showcase/데모-재설계.md 5A.1); its endpoints run with the live runs. */
@Configuration(proxyBeanMethods = false)
public class LabConfiguration {

    @Bean
    LabComposer labComposer(ScenarioCatalog catalog, ObjectMapper json) {
        return new LabComposer(catalog, json);
    }

    @Bean
    LabStore labStore(NamedParameterJdbcTemplate jdbc, ObjectMapper json) {
        return new LabStore(jdbc, json);
    }
}
