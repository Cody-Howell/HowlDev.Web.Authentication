public static class AuthLibraryExtensions
{
    public static MeterProviderBuilder AddAuthMiddlewareMetrics(this MeterProviderBuilder builder)
    {
        return builder.AddMeter("HowlDev.Web.Authentication.Middleware");
    }
}