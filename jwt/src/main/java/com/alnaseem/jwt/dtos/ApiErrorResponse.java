package com.alnaseem.jwt.dtos;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

/**
 * Standard API error response payload returned by the global exception handler.
 * Contains HTTP status, request path, localized message and timestamp.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class ApiErrorResponse {
    HttpStatus httpStatus;
    String path;
    String message;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd/MM/yyyy' 'HH:mm:ss")
    LocalDateTime timestamp;

}
