package io.contexa.showcase.business.internal;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Request view seen by every control. It hides the internal headers and every client header the engine would
 * otherwise trust, and, when a verified context exists, reports the run's client address and device.
 */
final class InternalContextRequest extends HttpServletRequestWrapper {

    private static final String USER_AGENT = "User-Agent";
    private static final Set<String> HIDDEN_HEADERS = hiddenHeaders();
    private static final Set<String> HIDDEN_PREFIXES = Set.of("x-showcase-", "x-contexa-", "x-simulated-");

    private final InternalContext context;

    InternalContextRequest(HttpServletRequest request, InternalContext context) {
        super(request);
        this.context = context;
    }

    @Override
    public String getRemoteAddr() {
        return hasText(clientIp()) ? clientIp() : super.getRemoteAddr();
    }

    @Override
    public String getRemoteHost() {
        return hasText(clientIp()) ? clientIp() : super.getRemoteHost();
    }

    @Override
    public String getHeader(String name) {
        if (isHidden(name)) {
            return null;
        }
        if (overridesUserAgent(name)) {
            return context.device();
        }
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (isHidden(name)) {
            return Collections.emptyEnumeration();
        }
        if (overridesUserAgent(name)) {
            return Collections.enumeration(Set.of(context.device()));
        }
        return super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        Set<String> names = new LinkedHashSet<>();
        for (String name : Collections.list(super.getHeaderNames())) {
            if (!isHidden(name)) {
                names.add(name);
            }
        }
        if (context != null && hasText(context.device())
                && names.stream().noneMatch(USER_AGENT::equalsIgnoreCase)) {
            names.add(USER_AGENT);
        }
        return Collections.enumeration(names);
    }

    @Override
    public int getIntHeader(String name) {
        return isHidden(name) ? -1 : super.getIntHeader(name);
    }

    @Override
    public long getDateHeader(String name) {
        return isHidden(name) ? -1L : super.getDateHeader(name);
    }

    static boolean isHidden(String name) {
        if (name == null) {
            return false;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        if (HIDDEN_HEADERS.contains(lower)) {
            return true;
        }
        for (String prefix : HIDDEN_PREFIXES) {
            if (lower.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private boolean overridesUserAgent(String name) {
        return USER_AGENT.equalsIgnoreCase(name) && context != null && hasText(context.device());
    }

    private String clientIp() {
        return context == null ? null : context.clientIp();
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static Set<String> hiddenHeaders() {
        Set<String> names = new LinkedHashSet<>();
        for (String header : InternalContextHeaders.UNTRUSTED_CLIENT_HEADERS) {
            names.add(header.toLowerCase(Locale.ROOT));
        }
        return Set.copyOf(names);
    }
}
