package com.alnaseem.jwt.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO returned after successful authentication containing the access token, refresh token and expiry.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtTokenDto {
    private String accessToken;
    private String refreshToken;
    private long expiresInMs;
}