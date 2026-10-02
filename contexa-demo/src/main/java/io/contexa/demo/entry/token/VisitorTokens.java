package io.contexa.demo.entry.token;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.time.Duration;

public interface VisitorTokens {

    String generate();

    String read(HttpServletRequest request);

    String hash(String token);

    void set(HttpServletResponse response, String token, Duration lifetime);
}
