package io.contexa.contexaidentity.security.service.ott;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class MagicLinkHandler implements OneTimeTokenGenerationSuccessHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken token)
            throws IOException {String email = URLEncoder.encode(token.getUsername(), StandardCharsets.UTF_8);
        response.sendRedirect("/ott/sent?email=" + email);
    }
}
