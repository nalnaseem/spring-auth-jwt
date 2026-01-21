package com.alnaseem.jwt.configurations;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Delegates exceptions thrown by downstream filters to Spring's HandlerExceptionResolver
 * so the application's ControllerAdvice can translate them into HTTP responses.
 */
@Component
@Slf4j
public class ExceptionDelegatingFilter extends OncePerRequestFilter {

    private final HandlerExceptionResolver resolver;

    public ExceptionDelegatingFilter(
            @Qualifier("handlerExceptionResolver")
            HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) {

        log.info("ExceptionDelegatingFilter: Filtering request {}", request.getRequestURI());

        try {
            filterChain.doFilter(request, response);
        } catch (Exception ex) {
            resolver.resolveException(request, response, null, ex);
        }
    }

}
