package com.example.msauthentication.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SignupRequest(
        @NotBlank(message = "email is required")
        @Email(message = "invalid email")
        String email,

        @NotBlank(message = "password is required")
        @Size(min = 4, message = "password must have at least 4 characters")
        String password,

        @NotBlank(message = "name is required")
        String name
) {
}
