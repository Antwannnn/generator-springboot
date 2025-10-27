package <%= packageName %>.web.controllers;

<%_ if (authenticationTypes && authenticationTypes.includes('jwt')) { _%>
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import <%= packageName %>.config.security.JwtTokenProvider;
import <%= packageName %>.config.security.TokenBlacklistService;
import <%= packageName %>.model.request.LoginRequest;
import <%= packageName %>.model.response.JwtAuthenticationResponse;
<%_ } _%>
<%_ if (authenticationTypes && authenticationTypes.includes('oauth2-resource')) { _%>
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import java.util.Map;
<%_ } _%>

@RestController
@RequestMapping("/api/auth")
public class AuthController {

<%_ if (authenticationTypes.includes('jwt')) { _%>
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final TokenBlacklistService tokenBlacklistService;
<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>
    private final String logoutUrl;

    @Value("${spring.security.oauth2.resourceserver.jwt.single-logout-enabled:false}")
    private boolean singleLogoutEnabled;
    
    @Value("${spring.security.oauth2.resourceserver.jwt.token-url}")
    private String tokenUrl;
    
    @Value("${spring.security.oauth2.resourceserver.client.client_id}")
    private String clientId;
    
    @Value("${spring.security.oauth2.resourceserver.client.client_secret}")
    private String clientSecret;
    
    private final RestTemplate restTemplate = new RestTemplate();
<%_ } _%>

    public AuthController(
            AuthenticationManager authenticationManager,
            JwtTokenProvider tokenProvider,
            TokenBlacklistService tokenBlacklistService<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>,
            @Value("${spring.security.oauth2.resourceserver.jwt.logout-url}") String logoutUrl<%_ } _%>
    ) {
        this.authenticationManager = authenticationManager;
        this.tokenProvider = tokenProvider;
        this.tokenBlacklistService = tokenBlacklistService;
<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>
        this.logoutUrl = logoutUrl;
<%_ } _%>
    }
<%_ } _%>
<%_ if (authenticationTypes.includes('oauth2-resource') && !authenticationTypes.includes('jwt')) { _%>
    @Value("${app.security.oauth2.logout-url}")
    private final String logoutUrl;
    
    @Value("${spring.security.oauth2.resourceserver.jwt.token-url}")
    private String tokenUrl;
    
    @Value("${spring.security.oauth2.resourceserver.client.client_id}")
    private String clientId;
    
    @Value("${spring.security.oauth2.resourceserver.client.client_secret}")
    private String clientSecret;
    
    private final RestTemplate restTemplate = new RestTemplate();
<%_ } _%>

<%_ if (authenticationTypes.includes('jwt')) { _%>
    @PostMapping("/login")
    public ResponseEntity<JwtAuthenticationResponse> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.generateToken(authentication);

        return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(Authentication authentication, @RequestHeader(value = "Authorization") String token) {

        if (authentication == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String resUrl = null;
        if (authentication.getPrincipal() instanceof Jwt jwt) {
<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>
            if(!jwt.getIssuer().toString().equals(tokenProvider.getLocalIssuerUri()) && singleLogoutEnabled){
                resUrl = logoutUrl;
            }
<%_ } _%>
            tokenBlacklistService.blacklistToken(jwt.getTokenValue());
        }
        else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        SecurityContextHolder.clearContext();

        if (resUrl != null) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header("Location", resUrl)
                    .build();
        } else {
            return ResponseEntity.ok("Successfully logged out.");
        }
    }
<%_ } _%>

<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>
    
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String,String> body) {
        String refreshToken = body.get("refresh_token");
        if (refreshToken == null) return ResponseEntity.badRequest().build();

        // Appel à Keycloak pour rafraîchir le token
        MultiValueMap<String,String> params = new LinkedMultiValueMap<>();
        params.add("grant_type","refresh_token");
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("refresh_token", refreshToken);

        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, params, Map.class);
        return ResponseEntity.ok(response.getBody());
    }
<%_ } _%>
}
