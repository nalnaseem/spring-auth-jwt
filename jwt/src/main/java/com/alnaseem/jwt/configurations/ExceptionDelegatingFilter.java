package com.alnaseem.jwt.configurations;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
//@RequiredArgsConstructor
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
                                    FilterChain filterChain)
            throws ServletException, IOException {

        log.info("ExceptionDelegatingFilter: Filtering request {}", request.getRequestURI());

        try {
            filterChain.doFilter(request, response);
        } catch (Exception ex) {
            resolver.resolveException(request, response, null, ex);
        }
    }

}
