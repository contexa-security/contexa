package io.contexa.demo.comparison.dispatch.http;

import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class PlannedBusinessRequest extends HttpServletRequestWrapper {

    private final byte[] body;

    public PlannedBusinessRequest(HttpServletRequest request, byte[] body) {
        super(request);
        this.body = body.clone();
    }

    @Override
    public ServletInputStream getInputStream() {
        return new BufferedRequestBody(body);
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }
}
