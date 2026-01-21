package com.alnaseem.jwt.controllers;

import com.alnaseem.jwt.dtos.JwtTokenDto;
import com.alnaseem.jwt.dtos.LoginRequest;
import com.alnaseem.jwt.dtos.RefreshTokenRequest;
import com.alnaseem.jwt.exceptions.InvalidCredentialsException;
import com.alnaseem.jwt.services.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

@RestController
@RequiredArgsConstructor
@RequestMapping("/v1/auth")
public class AuthenticationController {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {

        UserDetails user = userDetailsService.loadUserByUsername(req.getUsername());
        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            throw new InvalidCredentialsException();
        }

        JwtTokenDto pair = tokenService.generateTokens(user.getUsername());
        return ResponseEntity.ok(pair);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody RefreshTokenRequest req) {
        JwtTokenDto pair = tokenService.refreshAccessToken(req.getRefreshToken());
        if (pair == null) {
            throw new InvalidCredentialsException("invalid.expired.refresh.token");
        }

        return ResponseEntity.ok(pair);
    }
}
