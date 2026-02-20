package <%= packageName %>.config.logging.performance;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class PerformanceLogAspect {

    private final PerformanceLogger performanceLogger;

    public PerformanceLogAspect(PerformanceLogger performanceLogger) {
        this.performanceLogger = performanceLogger;
    }

    @Around("@annotation(<%= packageName %>.config.logging.performance.Performance)")
    public Object logPerformance(ProceedingJoinPoint joinPoint) throws Throwable {
        long start = System.currentTimeMillis();
        Object result = joinPoint.proceed();
        long duration = System.currentTimeMillis() - start;

        PerformanceLogEntry entry = new PerformanceLogEntry(
                joinPoint.getSignature().toShortString(),
                duration
        );
        performanceLogger.log(entry);
        return result;
    }
}