package <%= packageName %>.web.controllers;

<%_ if (authenticationTypes && authenticationTypes.includes('jwt')) { _%>
import com.nimbusds.jose.JOSEException;
import <%= packageName %>.model.entity.User;
import <%= packageName %>.model.request.SignupRequest;
import <%= packageName %>.repositories.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import <%= packageName %>.config.security.JwtService;
import <%= packageName %>.model.request.LoginRequest;
import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.util.Map;
<%_ } _%>
<%_ if (authenticationTypes && authenticationTypes.includes('oauth2-resource')) { _%>
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
<%_ } _%>

@RestController
@RequestMapping("/api/auth")
<%_ if (authenticationTypes.includes('jwt')) { _%>
@Slf4j
<%_ } _%>
public class AuthController {

<%_ if (authenticationTypes.includes('jwt')) { _%>
    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
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
            JwtService jwtService,
            PasswordEncoder passwordEncoder,
            UserRepository userRepository<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>,
            @Value("${spring.security.oauth2.resourceserver.jwt.logout-url}") String logoutUrl<%_ } _%>    ) {
        this.authManager = authenticationManager;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
<%_ if (authenticationTypes.includes('oauth2-resource')) { _%>
        this.logoutUrl = logoutUrl;
<%_ } _%>
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        if(authentication == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(authentication);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletResponse response, Authentication authentication) throws JOSEException {
        if(authentication != null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        String accessToken = jwtService.generateAccessToken(auth.getName());

        String refreshToken = jwtService.generateRefreshToken(auth.getName());

        ResponseCookie accessCookie = ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Strict")
                .maxAge(Duration.ofMinutes(15))
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Strict")
                .maxAge(Duration.ofDays(7))
                .build();

        response.setHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        return ResponseEntity.ok(Map.of("message","Login successful"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        ResponseCookie clearAccessToken = ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Strict")
                .maxAge(0)
                .build();

        ResponseCookie clearRefreshToken = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Strict")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, clearAccessToken.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, clearRefreshToken.toString());

        return ResponseEntity.ok(Map.of("message", "Logout successful"));
    }

    @PostMapping("/signup")
    public ResponseEntity<User> signup(@RequestBody SignupRequest signupRequest, Authentication authentication) {
        if(authentication != null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if(signupRequest.getEmail() != null && !signupRequest.getEmail().isEmpty()) {
            if(userRepository.existsByUsername(signupRequest.getUsername())) {
                return ResponseEntity.status(HttpStatus.CONFLICT).build();
            }

            User user = new User();
            user.setUsername(signupRequest.getUsername());
            user.setEmail(signupRequest.getEmail());
            user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
            user.setRole("ROLE_USER");
            user.setEnabled(true);
            userRepository.save(user);

            return ResponseEntity.ok(user);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) throws JOSEException {
        String refreshToken = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                }
            }
        }

        if (refreshToken != null && jwtService.validateToken(refreshToken)) {
            String username = jwtService.extractUsername(refreshToken);
            String newAccessToken = jwtService.generateAccessToken(username);

            ResponseCookie accessCookie = ResponseCookie.from("access_token", newAccessToken)
                    .httpOnly(true)
                    .path("/")
                    .sameSite("Strict")
                    .maxAge(Duration.ofMinutes(15))
                    .build();

            response.setHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
            return ResponseEntity.ok(Map.of("message","Access token refreshed"));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
    }
<%_ } _%>
}
