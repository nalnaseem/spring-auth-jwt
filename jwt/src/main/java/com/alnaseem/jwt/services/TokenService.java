package com.alnaseem.jwt.services;

import com.alnaseem.jwt.dtos.JwtTokenDto;
import com.alnaseem.jwt.entities.JwtToken;
import com.alnaseem.jwt.entities.TokenType;
import com.alnaseem.jwt.exceptions.JwtExpiredException;
import com.alnaseem.jwt.repositories.TokenRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/**
 * Service responsible for creating, validating and persisting JWT access and refresh tokens.
 * - Creates signed JWTs (HS256) and stores them in the `tokens` table.
 * - Validates tokens, checks expiry and repository lookup for revocation.
 * - Provides refresh flow that invalidates previous access tokens.
 */
@Service
@RequiredArgsConstructor
public class TokenService {

    @Value("${jwt.access-token-ttl-ms:300000}")
    private long accessTokenTtlMs;
    @Value("${jwt.refresh-token-ttl-ms:604800000}")
    private long refreshTokenTtlMs;
    @Value("${jwt.secret:change-me-in-production}")
    private String jwtSecret;

    private final TokenRepository tokenRepository;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();
    private static final String HMAC_ALGO = "HmacSHA256";

    /**
     * Generate a new access token and refresh token pair for the given username.
     * Persists both tokens and soft-deletes any previous tokens for the user.
     *
     * @param username the user identifier (subject)
     * @return JwtTokenDto containing accessToken, refreshToken, and access expiry
     */
    @Transactional
    public JwtTokenDto generateTokens(String username) {

        long now = Instant.now().toEpochMilli();
        String accessJwt = createJwt(username, now, accessTokenTtlMs, "access");
        String refreshJwt = createJwt(username, now, refreshTokenTtlMs, "refresh");

        JwtToken accessToken = JwtToken.builder()
                .token(accessJwt)
                .username(username)
                .expiresAt(Instant.ofEpochMilli(now + accessTokenTtlMs))
                .type(TokenType.ACCESS)
                .build();

        JwtToken refreshToken = JwtToken.builder()
                .token(refreshJwt)
                .username(username)
                .expiresAt(Instant.ofEpochMilli(now + refreshTokenTtlMs))
                .type(TokenType.REFRESH)
                .build();

        invalidateTokensForUser(username);

        tokenRepository.saveAndFlush(accessToken);
        tokenRepository.saveAndFlush(refreshToken);

        return new JwtTokenDto(accessJwt, refreshJwt, accessTokenTtlMs);
    }

    /**
     * Soft-delete all tokens for the specified username (mark active=false).
     *
     * @param username the username whose tokens should be invalidated
     */
    private void invalidateTokensForUser(String username) {
        tokenRepository.softDeleteByUsername(username);
    }

    /**
     * Soft-delete access tokens for the given username (preserves refresh tokens).
     *
     * @param username the username whose access tokens should be invalidated
     */
    private void invalidateAccessTokensForUser(String username) {
        tokenRepository.softDeleteByTypeAndUsername(TokenType.ACCESS, username);
    }

    /**
     * Validate an access token string:
     * - verifies signature and structural validity
     * - checks exp claim and repository record
     * - throws JwtExpiredException when expired
     *
     * @param token JWT access token string
     * @return the username (subject) if valid; null otherwise
     */
    public String validateAccessToken(String token) {
        if (token == null) return null;
        Map<String, Object> claims = parseAndValidateJwt(token);
        if (claims == null) return null;

        Object expObj = claims.get("exp");
        if (expObj == null) return null;
        long exp = ((Number) expObj).longValue();
        long now = Instant.now().getEpochSecond();
        if (now > exp) {
            tokenRepository.softDeleteByToken(token);
            throw new JwtExpiredException("error.token.expired", token, claims);
        }

        Optional<JwtToken> infoOpt = tokenRepository.findByToken(token);
        if (infoOpt.isEmpty()) return null;
        JwtToken info = infoOpt.get();
        if (Instant.now().isAfter(info.getExpiresAt())) {
            tokenRepository.softDeleteByToken(token);
            return null;
        }

        return info.getUsername();
    }

    /**
     * Validate a refresh token string:
     * - verifies signature and structural validity
     * - checks exp claim and repository record
     *
     * @param token refresh JWT string
     * @return the username (subject) if valid; null otherwise
     */
    public String validateRefreshToken(String token) {
        if (token == null) return null;
        Map<String, Object> claims = parseAndValidateJwt(token);
        if (claims == null) return null;

        Object expObj = claims.get("exp");
        if (expObj == null) return null;
        long exp = ((Number) expObj).longValue();
        long now = Instant.now().getEpochSecond();
        if (now > exp) {
            tokenRepository.softDeleteByToken(token);
            return null;
        }

        Optional<JwtToken> infoOpt = tokenRepository.findByToken(token);
        if (infoOpt.isEmpty()) return null;
        JwtToken info = infoOpt.get();
        if (Instant.now().isAfter(info.getExpiresAt())) {
            tokenRepository.softDeleteByToken(token);
            return null;
        }

        return info.getUsername();
    }

    /**
     * Refresh the access token using a valid refresh token.
     * Invalidates previous access tokens for the user and persists a new access token.
     *
     * @param refreshToken existing refresh token string
     * @return new JwtTokenDto with new access token and the same refresh token; null when refresh invalid
     */
    public JwtTokenDto refreshAccessToken(String refreshToken) {
        String username = validateRefreshToken(refreshToken);
        if (username == null) return null;

        long now = Instant.now().toEpochMilli();
        String newAccess = createJwt(username, now, accessTokenTtlMs, "access");

        JwtToken accessToken = JwtToken.builder()
                .token(newAccess)
                .username(username)
                .expiresAt(Instant.ofEpochMilli(now + accessTokenTtlMs))
                .type(TokenType.ACCESS)
                .build();

        invalidateAccessTokensForUser(username);

        tokenRepository.save(accessToken);
        return new JwtTokenDto(newAccess, refreshToken, accessTokenTtlMs);
    }

    /**
     * Create a signed JWT (HS256) with standard claims (sub, iat, exp, jti) and a custom "type" claim.
     *
     * @param username subject
     * @param nowMillis issued-at time in milliseconds
     * @param ttlMillis time-to-live in milliseconds
     * @param type token semantic type ("access" or "refresh")
     * @return signed JWT string
     */
    private String createJwt(String username, long nowMillis, long ttlMillis, String type) {
        try {
            Map<String, Object> header = new HashMap<>();
            header.put("alg", "HS256");
            header.put("typ", "JWT");

            long iat = nowMillis / 1000L;
            long exp = iat + (ttlMillis / 1000L);
            String jti = UUID.randomUUID().toString();

            Map<String, Object> payload = new HashMap<>();
            payload.put("sub", username);
            payload.put("iat", iat);
            payload.put("exp", exp);
            payload.put("jti", jti);
            payload.put("type", type);

            String headerJson = MAPPER.writeValueAsString(header);
            String payloadJson = MAPPER.writeValueAsString(payload);

            String headerB64 = BASE64URL_ENCODER.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
            String payloadB64 = BASE64URL_ENCODER.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

            String signingInput = headerB64 + "." + payloadB64;
            String signature = sign(signingInput, jwtSecret);

            return signingInput + "." + signature;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create JWT", e);
        }
    }

    /**
     * Parse the JWT payload and validate its signature using the configured secret.
     * Returns the claims map on success or null on any validation/parsing failure.
     *
     * @param jwt full JWT string
     * @return claims map or null if invalid
     */
    private Map<String, Object> parseAndValidateJwt(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) return null;
            String headerB64 = parts[0];
            String payloadB64 = parts[1];
            String signature = parts[2];

            String signingInput = headerB64 + "." + payloadB64;
            String expectedSig = sign(signingInput, jwtSecret);
            if (!constantTimeEquals(expectedSig, signature)) return null;

            String payloadJson = new String(BASE64URL_DECODER.decode(payloadB64), StandardCharsets.UTF_8);
            Map<String, Object> claims = MAPPER.readValue(payloadJson, new TypeReference<>() {
            });
            return claims;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Create HMAC-SHA256 signature for the given data using the provided secret and
     * return the Base64URL-encoded signature string.
     *
     * @param data signing input
     * @param secret secret key
     * @return signature string
     * @throws Exception if the MAC initialization or computation fails
     */
    private String sign(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGO);
        mac.init(keySpec);
        byte[] sig = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return BASE64URL_ENCODER.encodeToString(sig);
    }

    /**
     * Constant-time equality comparison to avoid timing attacks when comparing signatures.
     *
     * @param a first string
     * @param b second string
     * @return true if equal, false otherwise
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] A = a.getBytes(StandardCharsets.UTF_8);
        byte[] B = b.getBytes(StandardCharsets.UTF_8);
        if (A.length != B.length) return false;
        int result = 0;
        for (int i = 0; i < A.length; i++) {
            result |= A[i] ^ B[i];
        }
        return result == 0;
    }

}
