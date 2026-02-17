package <%= packageName %>.config.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class SecurityLogFilter extends OncePerRequestFilter {

    private SecurityLogger securityLogger;

    public SecurityLogFilter(SecurityLogger securityLogger) {
        this.securityLogger = securityLogger;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        long start = System.currentTimeMillis();
        boolean success = false;
        String username = "anonymous";

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null
                && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {

                username = authentication.getName();
                success = true;
        }

        filterChain.doFilter(request, response);

        long duration = System.currentTimeMillis() - start;

        SecurityLogEntry entry = new SecurityLogEntry(
                username,
                request.getRequestURI(),
                request.getMethod(),
                response.getStatus(),
                duration,
                getClientIp(request),
                request.getHeader("User-Agent"),
                success
        );

        securityLogger.logAccess(entry);
    }

    private String getClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}