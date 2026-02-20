package <%= packageName %>.config.logging.performance;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class PerformanceLogger {

    private static final Logger LOGGER = LoggerFactory.getLogger("PERFORMANCE");

    public void log(PerformanceLogEntry entry) {
        LOGGER.info(
                "signature='{}' duration='{}'",
                entry.signature(),
                entry.duration());
    }
}