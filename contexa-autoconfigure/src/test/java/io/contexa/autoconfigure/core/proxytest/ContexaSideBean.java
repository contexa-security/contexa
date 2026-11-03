package io.contexa.autoconfigure.core.proxytest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** A bean that a Contexa package defines (this package stands in for a Contexa library): a class without an interface. */
public class ContexaSideBean {

    public String work() {
        return "worked";
    }

    @Configuration(proxyBeanMethods = false)
    public static class Definition {

        @Bean
        ContexaSideBean contexaSideBean() {
            return new ContexaSideBean();
        }
    }
}
