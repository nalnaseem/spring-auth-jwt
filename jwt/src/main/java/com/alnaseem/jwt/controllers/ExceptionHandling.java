package com.alnaseem.jwt.controllers;

import com.alnaseem.jwt.configurations.MessageResolver;
import com.alnaseem.jwt.dtos.ApiErrorResponse;
import com.alnaseem.jwt.dtos.ApiValidationErrorResponse;
import com.alnaseem.jwt.exceptions.InvalidCredentialsException;
import com.alnaseem.jwt.exceptions.JwtExpiredException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.LocalDateTime;

@ControllerAdvice
@RequiredArgsConstructor
@Slf4j
public class ExceptionHandling extends ResponseEntityExceptionHandler {
    private final MessageResolver messages;
    private final HttpServletRequest request;

    public ResponseEntity<Object> buildApiErrorResponse(HttpStatus httpStatus, String messageKey) {
        var error = ApiErrorResponse.builder()
                .httpStatus(httpStatus)
                .path(request.getRequestURI())
                .message(messages.get(messageKey))
                .timestamp(LocalDateTime.now())
                .build();

        return ResponseEntity.status(httpStatus).body(error);
    }


    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Object> handleInvalidCredentials(InvalidCredentialsException ex) {
        log.warn("Invalid credentials attempt: {}", request.getRemoteAddr());
        return buildApiErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    @ExceptionHandler(JwtExpiredException.class)
    public ResponseEntity<Object> handleJwtExpired(JwtExpiredException ex) {
        log.warn("Expired JWT token: {} - remote={} - uri={}", ex.getMessage(), request.getRemoteAddr(), request.getRequestURI());
        return buildApiErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage());
    }

    // Handle Spring Security AuthorizationDeniedException (returns 403 Forbidden)
    @ExceptionHandler(AuthorizationDeniedException.class)
    public ResponseEntity<Object> handleAuthorizationDenied(AuthorizationDeniedException ex) {
        log.warn("Access denied: {} - remote={} - uri={}", ex.getMessage(), request.getRemoteAddr(), request.getRequestURI());
        return buildApiErrorResponse(HttpStatus.FORBIDDEN, "error.forbidden");
    }

    // Also handle the older AccessDeniedException to cover different security paths
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> handleAccessDenied(AccessDeniedException ex) {
        log.warn("Access denied (access denied exc): {} - remote={} - uri={}", ex.getMessage(), request.getRemoteAddr(), request.getRequestURI());
        return buildApiErrorResponse(HttpStatus.FORBIDDEN, "error.forbidden");
    }

    private ApiValidationErrorResponse buildApiValidationErrorResponse() {
        return ApiValidationErrorResponse.builder()
                .httpStatus(HttpStatus.BAD_REQUEST)
                .path(this.request.getRequestURI())
                .message(messages.get("error.validation"))
                .timestamp(LocalDateTime.now())
                .build();
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.error("HttpMessageNotReadableException", ex);

        return buildApiErrorResponse(HttpStatus.BAD_REQUEST, "error.malformed.json");
    }

    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.error("MethodArgumentNotValidException", ex);

        ApiValidationErrorResponse error = buildApiValidationErrorResponse();

        ex.getBindingResult().getFieldErrors().forEach(fieldError -> {
            error.addValidationError(fieldError.getField(),
                    messages.get(fieldError.getDefaultMessage()));
        });

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }


    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Object> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        log.error("DataIntegrityViolationException", ex);
        return buildApiErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "error.internal");
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Object> handleConstraintViolation(ConstraintViolationException ex) {
        log.error("ConstraintViolationException", ex);
        return buildApiErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "error.internal");
    }

    @ExceptionHandler(InvalidDataAccessResourceUsageException.class)
    public ResponseEntity<Object> handleInvalidDataAccessResourceUsage(InvalidDataAccessResourceUsageException ex) {
        log.error("InvalidDataAccessResourceUsageException", ex);
        return buildApiErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "error.internal");
    }
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        log.error("HttpRequestMethodNotSupportedException", ex);
        return buildApiErrorResponse(HttpStatus.METHOD_NOT_ALLOWED, "error.method.not.allowed");
    }}
