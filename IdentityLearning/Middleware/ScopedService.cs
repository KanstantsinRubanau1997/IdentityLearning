namespace IdentityLearning.Middleware
{
    public class ScopedService
    {
        private readonly ILogger _logger;

        public ScopedService(ILogger<ScopedService> logger) => _logger = logger;

        public void DoSomething()
        {
            _logger.LogInformation("From ScopedService");
        }
    }
}
