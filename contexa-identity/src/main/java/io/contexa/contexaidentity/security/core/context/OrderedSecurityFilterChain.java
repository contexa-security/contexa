package io.contexa.contexaidentity.security.core.context;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;

public class OrderedSecurityFilterChain implements SecurityFilterChain, Ordered {

    private final DefaultSecurityFilterChain delegate;

    private final int order;

    public OrderedSecurityFilterChain(int order, RequestMatcher matcher, List<Filter> filters) {
        this.delegate = new DefaultSecurityFilterChain(matcher, filters);
        this.order = order;
    }

    @Override
    public int getOrder() {
        return order;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return delegate.matches(request);
    }

    @Override
    public List<Filter> getFilters() {
        return delegate.getFilters();
    }
}

