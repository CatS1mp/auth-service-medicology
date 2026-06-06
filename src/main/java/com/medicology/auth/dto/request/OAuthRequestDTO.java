package com.medicology.auth.dto.request;

import jakarta.validation.constraints.*;

public record OAuthRequestDTO(
    @NotBlank(message = "Cần access token từ nhà cung cấp OAuth.")
    String accessToken,

    @NotBlank(message = "Cần chỉ định nhà cung cấp OAuth (google / facebook).")
    String provider
) {}
