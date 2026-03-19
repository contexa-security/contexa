package io.contexa.contexaidentity.security.core.adapter.state.session;

import io.contexa.contexaidentity.security.core.adapter.StateAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexacommon.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.util.Objects;

public class SessionStateAdapter implements StateAdapter {

    @Override
    public String getId() {
        return "session";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext platformCtx) throws Exception {
        apply(http, platformCtx, null);
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext platformCtx, AuthenticationFlowConfig flowConfig) throws Exception {

        ApplicationContext appContext = Objects.requireNonNull(platformCtx.applicationContext(), "ApplicationContext from PlatformContext cannot be null");
        LogoutHandler logoutHandler = appContext.getBean("compositeLogoutHandler", LogoutHandler.class);

        String urlPrefix = flowConfig != null ? flowConfig.getUrlPrefix() : null;
        String logoutUrl = urlPrefix != null ? urlPrefix + "/logout" : "/logout";

        String logoutSuccessUrl;
        if (urlPrefix != null && flowConfig != null && MfaFlowTypeUtils.isMfaFlow(flowConfig.getTypeName())) {
            AuthContextProperties authProps = appContext.getBean(AuthContextProperties.class);
            String primaryLoginPage = authProps.getUrls().getPrimary().getFormLoginPage();
            logoutSuccessUrl = urlPrefix + primaryLoginPage;
        } else {
            logoutSuccessUrl = "/login";
        }

        http.logout(logout -> logout
                .logoutUrl(logoutUrl)
                .logoutSuccessUrl(logoutSuccessUrl)
                .addLogoutHandler(logoutHandler)
                .invalidateHttpSession(true)
                .clearAuthentication(true)
        );

        SessionStateConfigurer configurer = new SessionStateConfigurer(appContext);
        http.with(configurer, Customizer.withDefaults());
    }
}
