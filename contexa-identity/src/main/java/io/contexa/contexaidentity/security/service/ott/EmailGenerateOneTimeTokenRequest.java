package io.contexa.contexaidentity.security.service.ott;

import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;

public class EmailGenerateOneTimeTokenRequest extends GenerateOneTimeTokenRequest {
    
    private final String email;

    public EmailGenerateOneTimeTokenRequest(String username, String email) {
        super(username);
        this.email = email;
    }

    public String getEmail() {
        return this.email;
    }
}
