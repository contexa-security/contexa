package io.contexa.site;

import io.contexa.contexacommon.annotation.EnableAISecurity;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableAISecurity(mode = SecurityMode.FULL)
public class ContexaSiteApplication {

    public static void main(String[] args) {
        SpringApplication.run(ContexaSiteApplication.class, args);
    }
}
