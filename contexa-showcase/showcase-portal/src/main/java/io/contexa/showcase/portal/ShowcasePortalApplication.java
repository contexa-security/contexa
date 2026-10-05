package io.contexa.showcase.portal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Visitor-facing portal of the Contexa Showcase: serves the web experience, orchestrates runs
 * against the five controls and keeps the evidence of every run.
 */
@SpringBootApplication(exclude = HibernateJpaAutoConfiguration.class)
@ConfigurationPropertiesScan
public class ShowcasePortalApplication {

    public static void main(String[] args) {
        SpringApplication.run(ShowcasePortalApplication.class, args);
    }
}
