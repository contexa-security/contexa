package io.contexa.springbootstartercontexa;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableAISecurity
public class SpringBootStarterContexaApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootStarterContexaApplication.class, args);
    }

}