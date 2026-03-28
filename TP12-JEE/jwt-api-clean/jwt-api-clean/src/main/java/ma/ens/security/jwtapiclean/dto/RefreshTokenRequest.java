package ma.ens.security.jwtapiclean.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Requête de rafraîchissement de token
 * Token refresh request DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenRequest {

    @NotBlank(message = "Refresh token requis / Refresh token required")
    private String refreshToken;
}