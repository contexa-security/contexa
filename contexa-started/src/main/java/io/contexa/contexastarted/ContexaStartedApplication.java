package io.contexa.contexastarted;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableAISecurity(mode = SecurityMode.FULL)
public class ContexaStartedApplication {

    public static void main(String[] args) {
        SpringApplication.run(ContexaStartedApplication.class, args);
    }

}
