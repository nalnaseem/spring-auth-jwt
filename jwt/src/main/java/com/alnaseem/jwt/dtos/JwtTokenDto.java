package com.alnaseem.jwt.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtTokenDto {
    private String accessToken;
    private String refreshToken;
    private long expiresInMs;
}