using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace UserService.AuthenticationAndAuthorization;

public class DebugRoleAuthorizationHandler(ILogger<DebugRoleAuthorizationHandler> logger)
    : AuthorizationHandler<RolesAuthorizationRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RolesAuthorizationRequirement requirement)
    {
        if (context.User.Identity is { IsAuthenticated: false })
        {
            logger.LogWarning("User is not authenticated.");
            return Task.CompletedTask;
        }

        var userRoles = context.User.FindAll(ClaimTypes.Role);

        var enumerable = userRoles as Claim[] ?? userRoles.ToArray();
        foreach (var role in enumerable)
        {
            logger.LogInformation($"User is in role: {role.Value}");
        }

        var isAuthorized = enumerable.Any(r => requirement.AllowedRoles.Contains(r.Value));

        if (isAuthorized)
        {
            context.Succeed(requirement);
        }
        else
        {
            logger.LogWarning("User is not in the required role.");
        }

        return Task.CompletedTask;
    }
}
