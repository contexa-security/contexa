package io.contexa.contexaidentity.security.core.adapter.state.session;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

public class SessionStateConfigurer extends AbstractHttpConfigurer<SessionStateConfigurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) {
//        System.out.println( "SessionStateConfigurer.init()");
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
//        System.out.println( "SessionStateConfigurer.configure()");
    }
}
