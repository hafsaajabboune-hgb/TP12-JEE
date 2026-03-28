package ma.ens.security.jwtapiclean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtre d'authentification JWT
 * JWT Authentication Filter
 *
 * Intercepte chaque requête, extrait et valide le token JWT
 * Intercepts every request, extracts and validates the JWT token
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        log.debug("Filtre JWT exécuté pour / JWT filter executing for: {}", requestURI);

        try {
            String jwt = extractJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && SecurityContextHolder.getContext().getAuthentication() == null) {
                String username = jwtTokenProvider.extractUsername(jwt);
                log.debug("Nom d'utilisateur extrait / Username extracted: {}", username);

                if (username != null) {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    log.debug("Autorités chargées / Authorities loaded: {}", userDetails.getAuthorities());

                    if (jwtTokenProvider.validateToken(jwt, userDetails)) {
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(
                                        userDetails,
                                        null,
                                        userDetails.getAuthorities()
                                );

                        authentication.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request)
                        );

                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        log.debug("Authentification réussie pour / Authentication successful for: {}", username);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Erreur lors de l'authentification JWT / JWT authentication error: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extrait le token JWT du header Authorization
     * Extracts JWT token from Authorization header
     */
    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }
}