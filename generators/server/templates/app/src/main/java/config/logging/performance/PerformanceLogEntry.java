package <%= packageName %>.config.logging.performance;

public record PerformanceLogEntry(
        String signature,
        long duration
) {
}