package io.contexa.contexamcp;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableAspectJAutoProxy
@EnableJpaAuditing
@EnableJpaRepositories(basePackages = {"io.contexa.contexacommon.repository"})
@EntityScan(basePackages = {"io.contexa.contexacommon.entity"})
@SpringBootApplication
@RequiredArgsConstructor
public class ContexaMcpApplication {

    public static void main(String[] args) {
        SpringApplication.run(ContexaMcpApplication.class, args);
    }

}
