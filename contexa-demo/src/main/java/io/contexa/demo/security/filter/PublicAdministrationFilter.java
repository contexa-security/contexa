package io.contexa.demo.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Profile("public")
@Order(Ordered.HIGHEST_PRECEDENCE + 15)
public class PublicAdministrationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getServletPath();
        String username = "POST".equals(request.getMethod()) ? request.getParameter("username") : null;
        if (path.startsWith("/contexa/admin") || path.startsWith("/api/work/admin/")
                || path.equals("/api/lab/access/admin") || path.startsWith("/api/lab/readiness/admin")
                || (username != null && !"user".equals(username))) {
            response.setStatus(404);
            response.setHeader("Cache-Control", "no-store");
            response.setContentType("application/json");
            response.getWriter().write("{\"state\":\"PUBLIC_ADMIN_UNAVAILABLE\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}
