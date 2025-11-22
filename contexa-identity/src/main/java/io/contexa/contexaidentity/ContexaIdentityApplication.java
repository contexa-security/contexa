package io.contexa.contexaidentity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableJpaRepositories(basePackages = {"io.contexa.contexacoreenterprise.repository","io.contexa.contexacore.repository","io.contexa.contexacommon.repository"})
@EntityScan(basePackages = {"io.contexa.contexacoreenterprise.domain.entity","io.contexa.contexacore.domain.entity","io.contexa.contexaidentity.domain.entity", "io.contexa.contexacommon.entity"})
@ComponentScan(basePackages = {"io.contexa.contexacoreenterprise","io.contexa.contexacore","io.contexa.contexaidentity","io.contexa.contexacommon"})
@EnableJpaAuditing
@SpringBootApplication
public class ContexaIdentityApplication {

    public static void main(String[] args) {
        SpringApplication.run(ContexaIdentityApplication.class, args);
    }

}