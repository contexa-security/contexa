package io.contexa.contexastarted;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableAISecurity
public class ContexaStartedApplication {

    public static void main(String[] args) {
        SpringApplication.run(ContexaStartedApplication.class, args);
    }

}
