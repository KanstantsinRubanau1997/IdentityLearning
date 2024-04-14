namespace IdentityLearning.Middleware
{
    public class StandartMiddleware
    {
        private readonly RequestDelegate _next;

        private readonly ILogger<StandartMiddleware> _logger;

        public StandartMiddleware(RequestDelegate next, ILogger<StandartMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            _logger.LogInformation("From standart middleware. Before action");

            await _next(context);

            _logger.LogInformation("From standart middleware. After action");
        }
    }
}
