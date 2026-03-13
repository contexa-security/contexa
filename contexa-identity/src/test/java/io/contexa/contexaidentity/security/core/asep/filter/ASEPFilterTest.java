package io.contexa.contexaidentity.security.core.asep.filter;

import io.contexa.contexaidentity.security.core.asep.handler.SecurityExceptionHandlerInvoker;
import io.contexa.contexaidentity.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.core.Ordered;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ASEPFilterTest {

    @Mock
    private SecurityExceptionHandlerMethodRegistry handlerRegistry;
    @Mock
    private SecurityExceptionHandlerInvoker handlerInvoker;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private FilterChain filterChain;

    private ASEPFilter filter;

    @BeforeEach
    void setUp() throws IOException {
        List<HttpMessageConverter<?>> converters = List.of(new MappingJackson2HttpMessageConverter());
        filter = new ASEPFilter(handlerRegistry, handlerInvoker, converters);

        when(request.getRequestURI()).thenReturn("/test/path");
        when(request.getHeader("Accept")).thenReturn("application/json");
        when(request.getDispatcherType()).thenReturn(DispatcherType.REQUEST);
        when(response.isCommitted()).thenReturn(false);
        when(response.getOutputStream()).thenReturn(createStubOutputStream());
    }

    @Test
    void shouldPassThrough_whenNoException() throws Exception {
        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(handlerRegistry, never()).findBestExceptionHandlerMethod(any(), any(), any());
    }

    @Test
    void shouldReturn401_forAuthenticationException() throws Exception {
        doThrow(new BadCredentialsException("Bad credentials"))
                .when(filterChain).doFilter(request, response);
        when(handlerRegistry.findBestExceptionHandlerMethod(any(), any(), any())).thenReturn(null);

        SecurityContextImpl securityContext = new SecurityContextImpl();
        SecurityContextHolder.setContext(securityContext);

        filter.doFilter(request, response, filterChain);

        verify(response).setStatus(401);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();

        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldReturn403_forAccessDeniedException() throws Exception {
        doThrow(new AccessDeniedException("Access denied"))
                .when(filterChain).doFilter(request, response);
        when(handlerRegistry.findBestExceptionHandlerMethod(any(), any(), any())).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        verify(response).setStatus(403);
    }

    @Test
    void shouldReturn500_forGenericException() throws Exception {
        doThrow(new RuntimeException("Unexpected error"))
                .when(filterChain).doFilter(request, response);
        when(handlerRegistry.findBestExceptionHandlerMethod(any(), any(), any())).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        verify(response).setStatus(500);
    }

    @Test
    void getOrder_shouldReturnConfiguredOrder() {
        int expectedOrder = Ordered.LOWEST_PRECEDENCE - 900;

        assertThat(filter.getOrder()).isEqualTo(expectedOrder);
    }

    @Test
    void shouldHandleCommittedResponse_gracefully() throws Exception {
        IOException ioException = new IOException("Connection reset");
        doThrow(ioException).when(filterChain).doFilter(request, response);
        when(response.isCommitted()).thenReturn(true);

        assertThatThrownBy(() -> filter.doFilter(request, response, filterChain))
                .isInstanceOf(IOException.class)
                .hasMessage("Connection reset");
    }

    private static ServletOutputStream createStubOutputStream() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        return new ServletOutputStream() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener writeListener) {
                // no-op
            }

            @Override
            public void write(int b) {
                baos.write(b);
            }
        };
    }
}
