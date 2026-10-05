package io.contexa.showcase.workload.plain;

import io.contexa.showcase.business.EnableShowcaseBusiness;
import io.contexa.showcase.business.internal.EnableShowcaseInternalContext;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Business application protected without Contexa. One instance runs per control: B (RBAC), C1 (threshold rules)
 * or C2 (context lookup rules), selected by showcase.control; control A is the WAF in front of instance B
 * (docs/showcase/ADR.md ADR-20).
 */
@SpringBootApplication(scanBasePackages = "io.contexa.showcase.workload.plain",
        exclude = HibernateJpaAutoConfiguration.class)
@ConfigurationPropertiesScan(basePackages = "io.contexa.showcase")
@EnableShowcaseInternalContext
@EnableShowcaseBusiness
public class PlainWorkloadApplication {

    public static void main(String[] args) {
        SpringApplication.run(PlainWorkloadApplication.class, args);
    }
}
