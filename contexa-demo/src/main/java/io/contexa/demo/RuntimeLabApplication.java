package io.contexa.demo;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication(exclude = HibernateJpaAutoConfiguration.class)
@ConfigurationPropertiesScan
@EnableAISecurity(mode = SecurityMode.FULL)
public class RuntimeLabApplication {

    public static void main(String[] args) {
        SpringApplication.run(RuntimeLabApplication.class, args);
    }
}
