package <%= packageName %>.config.logging.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class SecurityLogger {

    private static final Logger LOGGER =
            LoggerFactory.getLogger("SECURITY");

    public void logAccess(SecurityLogEntry entry) {
        LOGGER.info(
                "user='{}' path='{}' method={} status={} duration={}ms ip='{}' user-agent='{}' success={}",
                entry.username(),
                entry.path(),
                entry.method(),
                entry.status(),
                entry.durationMs(),
                entry.ip(),
                entry.userAgent(),
                entry.success()
        );
    }
}