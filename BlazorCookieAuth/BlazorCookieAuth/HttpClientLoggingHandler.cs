namespace BlazorCookieAuth;

public class HttpClientLoggingHandler() : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Headers.Contains("Cookie"))
        {
            var cookieHeader = request.Headers.GetValues("Cookie").FirstOrDefault();
            Console.WriteLine($"Sending Cookie: {cookieHeader}");
        }
        else
        {
            Console.WriteLine("No Cookie header present in the request.");
        }

        // Continue with the request
        return await base.SendAsync(request, cancellationToken);
    }
}