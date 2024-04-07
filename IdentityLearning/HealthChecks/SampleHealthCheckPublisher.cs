using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace IdentityLearning.HealthChecks
{
    public class SampleHealthCheckPublisher : IHealthCheckPublisher
    {
        private readonly ILogger _logger;


        public SampleHealthCheckPublisher(ILogger<SampleHealthCheckPublisher> logger)
        {
            _logger = logger;
        }


        public Task PublishAsync(HealthReport report, CancellationToken cancellationToken)
        {
            if (report.Status == HealthStatus.Healthy)
            {
                _logger.LogInformation("App is healthy");
            }
            else
            {
                _logger.LogError("App is not healty");
            }

            return Task.CompletedTask;
        }
    }
}
