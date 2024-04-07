using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace IdentityLearning.HealthChecks
{
    public class SampleHealthCheck : IHealthCheck
    {
        public Task<HealthCheckResult> CheckHealthAsync(
            HealthCheckContext context,
            CancellationToken cancellationToken = default)
        {
            var isHealthy = true;

            if (isHealthy)
            {
                return Task.FromResult(HealthCheckResult.Healthy("Updated healthy result"));
            }

            return Task.FromResult(new HealthCheckResult(
                context.Registration.FailureStatus,
                "Somethign went wrong"));
        }
    }
}
