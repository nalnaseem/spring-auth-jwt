package com.alnaseem.jwt.exceptions;

public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException() {
        super("error.invalid.credentials");
    }

    public InvalidCredentialsException(String messageKey) {
        super(messageKey);
    }
}
