package io.contexa.contexaidentity.security.filter.handler;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.matcher.MfaRequestType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface MfaRequestHandler {

    void handleRequest(MfaRequestType requestType, HttpServletRequest request,
                       HttpServletResponse response, FactorContext context,
                       FilterChain filterChain) throws ServletException, IOException;

    void handleTerminalContext(HttpServletRequest request, HttpServletResponse response,
                               FactorContext context) throws ServletException, IOException;

    void handleGenericError(HttpServletRequest request, HttpServletResponse response,
                            FactorContext context, Exception error) throws ServletException, IOException;
}