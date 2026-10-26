package com.vickynishad.tech.auth.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class AuthContracts {

    public record RegisterCommand(
            @NotBlank(message = "Email is required")
            @Email(message = "Format must be a valid email address")
            String email,

            @NotBlank(message = "Password cannot be blank")
            @Size(min = 8, max = 72, message = "Password must be between 8 and 72 characters")
            String password
    ) {
        public RegisterCommand {
            email = (email != null) ? email.trim().toLowerCase() : null;
        }
    }

    public record LoginCommand(
            @NotBlank @Email String email,
            @NotBlank String password
    ) {
        public LoginCommand {
            email = (email != null) ? email.trim().toLowerCase() : null;
        }
    }

    public record RefreshTokenCommand(
            @NotBlank String refreshToken
    ) {}

    public record AuthenticationEnvelope(
            String tokenType,
            String accessToken,
            String refreshToken,
            long expiresInSeconds
    ) {
        public AuthenticationEnvelope(String accessToken, String refreshToken, long expiresInSeconds) {
            this("Bearer", accessToken, refreshToken, expiresInSeconds);
        }
    }
}