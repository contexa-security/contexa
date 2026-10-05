package io.contexa.showcase.workload.contexa;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.showcase.business.EnableShowcaseBusiness;
import io.contexa.showcase.business.internal.EnableShowcaseInternalContext;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Control D: the same business application protected by the Contexa runtime engine in ENFORCE mode.
 */
@SpringBootApplication(scanBasePackages = "io.contexa.showcase.workload.contexa",
        exclude = HibernateJpaAutoConfiguration.class)
@ConfigurationPropertiesScan(basePackages = "io.contexa.showcase")
@EnableAISecurity(mode = SecurityMode.FULL)
@EnableShowcaseInternalContext
@EnableShowcaseBusiness
public class ContexaWorkloadApplication {

    public static void main(String[] args) {
        SpringApplication.run(ContexaWorkloadApplication.class, args);
    }
}
