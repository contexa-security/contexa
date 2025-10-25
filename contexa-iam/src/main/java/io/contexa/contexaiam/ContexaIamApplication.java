package io.contexa.contexaiam;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableJpaRepositories(basePackages = {"io.contexa.contexacore.repository", "io.contexa.contexaiam.repository", "io.contexa.contexacommon.repository"})
@EntityScan(basePackages = {"io.contexa.contexaiam.domain.entity","io.contexa.contexacore.domain.entity","io.contexa.contexacommon.entity"})
@ComponentScan(basePackages = {"io.contexa.contexaiam", "io.contexa.contexacore","io.contexa.contexacommon"})
@EnableAspectJAutoProxy(proxyTargetClass = true)
@EnableJpaAuditing
@SpringBootApplication
public class ContexaIamApplication {

    public static void main(String[] args) {
        SpringApplication.run(ContexaIamApplication.class, args);
    }

}
