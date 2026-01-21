package com.alnaseem.jwt.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Login request payload containing username and password. Validated for non-null/blank values.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {

    @NotNull(message = "{login.username.notnull}")
    @NotBlank(message = "{login.username.notblank}")
    private String username;

    @NotNull(message = "{login.password.notnull}")
    @NotBlank(message = "{login.password.notblank}")
    private String password;
}
