package io.contexa.contexaidentity.security.token.transport;

import lombok.Builder;
import lombok.Getter;
import org.springframework.http.ResponseCookie;

import java.util.List;
import java.util.Map;

@Getter
@Builder
public class TokenTransportResult {
    
    private final Map<String, Object> body;
    
    private final List<ResponseCookie> cookiesToSet;
    
    private final List<ResponseCookie> cookiesToRemove;
    
    private final Map<String, String> headers;

}
