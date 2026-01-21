package com.alnaseem.jwt.exceptions;

/**
 * Thrown when provided credentials are invalid (e.g., wrong username/password).
 * Message key is used for localization by the global exception handler.
 */
public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException() {
        super("error.invalid.credentials");
    }

    public InvalidCredentialsException(String messageKey) {
        super(messageKey);
    }
}
