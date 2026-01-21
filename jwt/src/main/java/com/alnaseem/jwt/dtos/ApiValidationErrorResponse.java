package com.alnaseem.jwt.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.util.ArrayList;
import java.util.List;

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
