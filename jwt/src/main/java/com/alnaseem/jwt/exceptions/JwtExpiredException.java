package com.alnaseem.jwt.exceptions;

import java.util.Map;

/**
 * Thrown when a JWT token is expired.
 * The exception message is intended to carry a message key (e.g. "error.token.expired")
 * so it can be localized by the application's MessageResolver / ExceptionHandling.
 *
 * This exception also carries the raw JWT string and the parsed claims map to allow
 * downstream handlers to log or inspect token details.
 */
public class JwtExpiredException extends RuntimeException {

    private final String jwt;
    private final Map<String, Object> claims;

    public JwtExpiredException() {
        super("error.token.expired");
        this.jwt = null;
        this.claims = null;
    }

    public JwtExpiredException(String messageKey) {
        super(messageKey);
        this.jwt = null;
        this.claims = null;
    }

    public JwtExpiredException(String messageKey, Throwable cause) {
        super(messageKey, cause);
        this.jwt = null;
        this.claims = null;
    }

    public JwtExpiredException(String jwt, Map<String, Object> claims) {
        super("error.token.expired");
        this.jwt = jwt;
        this.claims = claims;
    }

    public JwtExpiredException(String messageKey, String jwt, Map<String, Object> claims) {
        super(messageKey);
        this.jwt = jwt;
        this.claims = claims;
    }

    public JwtExpiredException(String messageKey, String jwt, Map<String, Object> claims, Throwable cause) {
        super(messageKey, cause);
        this.jwt = jwt;
        this.claims = claims;
    }

    public String getJwt() {
        return jwt;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }
}
