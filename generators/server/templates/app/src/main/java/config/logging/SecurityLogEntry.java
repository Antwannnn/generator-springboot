package <%= packageName %>.config.logging;

public record SecurityLogEntry(
        String username,
        String path,
        String method,
        int status,
        long durationMs,
        String ip,
        String userAgent,
        boolean success
) {}