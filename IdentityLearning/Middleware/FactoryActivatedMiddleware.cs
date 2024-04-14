
namespace IdentityLearning.Middleware
{
    public class FactoryActivatedMiddleware : IMiddleware
    {
        private readonly ScopedService _scopedService;

        public FactoryActivatedMiddleware(ScopedService scopedService)
        {
            _scopedService = scopedService;
        }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            _scopedService.DoSomething();

            await next(context);
        }
    }
}
