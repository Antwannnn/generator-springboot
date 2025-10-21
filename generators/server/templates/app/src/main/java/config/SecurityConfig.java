package <%= packageName %>.config;

<%_ if (authenticationTypes && authenticationTypes.length > 0) { _%>
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
<%_ if (authenticationTypes.includes('basic') || authenticationTypes.includes('jwt')) { _%>
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
<%_ } _%>
<%_ if (authenticationTypes.includes('oauth2-resource') || authenticationTypes.includes('sso')) { _%>
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
<%_ } _%>
<%_ if (authenticationTypes.includes('jwt')) { _%>
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import <%= packageName %>.config.security.JwtAuthenticationEntryPoint;
import <%= packageName %>.config.security.JwtAuthenticationFilter;
import <%= packageName %>.config.security.CustomUserDetailsService;
import <%= packageName %>.repositories.UserRepository;
<%_ } _%>

@Configuration
@EnableWebSecurity
public class SecurityConfig {

<%_ if (authenticationTypes.includes('jwt')) { _%>
    private final UserRepository userRepository;

    public SecurityConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
<%_ } _%>

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/actuator/**", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                <%_ if (authenticationTypes.includes('oauth2-client')) { _%>
                .requestMatchers("/oauth2/**", "/login/**").permitAll()
                <%_ } _%>
                <%_ if (authenticationTypes.includes('jwt')) { _%>
                .requestMatchers("/api/auth/**").permitAll()
                <%_ } _%>
                .anyRequest().authenticated()
            );

        <%_ if (authenticationTypes.includes('oauth2-resource') || authenticationTypes.includes('sso')) { _%>
        // OAuth2 Resource Server (JWT validation)
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            );
        <%_ } _%>

        <%_ if (authenticationTypes.includes('oauth2-client')) { _%>
        // OAuth2 Client (Social login)
        http.oauth2Login(oauth2 -> oauth2
            .defaultSuccessUrl("/", true)
            .failureUrl("/login?error=true")
        );
        <%_ } _%>

        <%_ if (authenticationTypes.includes('jwt')) { _%>
        // JWT Authentication
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> ex.authenticationEntryPoint(jwtAuthenticationEntryPoint()))
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        <%_ } _%>

        <%_ if (authenticationTypes.includes('basic')) { _%>
        // Basic Authentication
        http.httpBasic(basic -> basic.realmName("<%= appName %>"));
        <%_ } _%>

        return http.build();
    }

<%_ if (authenticationTypes.includes('oauth2-resource') || authenticationTypes.includes('sso')) { _%>
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix("ROLE_");
        authoritiesConverter.setAuthoritiesClaimName("roles");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }
<%_ } _%>

<%_ if (authenticationTypes.includes('jwt')) { _%>
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService(userRepository);
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    @Bean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint();
    }
<%_ } _%>

<%_ if (authenticationTypes.includes('basic') || authenticationTypes.includes('jwt')) { _%>
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
<%_ } _%>
}
<%_ } _%>