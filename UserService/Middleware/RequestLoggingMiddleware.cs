namespace UserService.Middleware;

public class RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        // Log the request details
        await LogRequest(context);

        // Call the next middleware in the pipeline
        await next(context);
    }

    private async Task LogRequest(HttpContext context)
    {
        // Log request method, path, headers, etc.
        logger.LogInformation("Request Method: {Method}", context.Request.Method);
        logger.LogInformation("Request Path: {Path}", context.Request.Path);
        logger.LogInformation("Request Headers: {Headers}", context.Request.Headers);
        
        // If you want to log the body, you need to enable buffering and then read the body
        context.Request.EnableBuffering();
        using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        logger.LogInformation("Request Body: {Body}", body);
        context.Request.Body.Position = 0; // Reset the body stream position
    }
}
