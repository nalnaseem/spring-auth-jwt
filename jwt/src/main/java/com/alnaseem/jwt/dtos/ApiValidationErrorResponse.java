package com.alnaseem.jwt.dtos;

import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * API validation error payload that extends ApiErrorResponse with field-level errors.
 * Contains a list of field errors for reporting validation failures back to clients.
 */
@EqualsAndHashCode(callSuper = true)
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class ApiValidationErrorResponse extends ApiErrorResponse {
    @Builder.Default
    List<FieldError> fieldErrors = new ArrayList<>();

    public void addValidationError(String field, String message) {
        fieldErrors.add(new FieldError(field, message));
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class FieldError {
        String field;
        String message;
    }
}
