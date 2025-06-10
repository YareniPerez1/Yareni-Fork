using CentraliaStore.Models;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace CentraliaStore.Authorization
{
    public class ApiKeyAuthorizationHandler : AuthorizationHandler<OperationAuthorizationRequirement, ApiKey>
    {
        protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        ApiKey resource)
        {
            if (context.User == null || resource == null)
            {
                return Task.CompletedTask;
            }

          
            if (context.User.IsInRole("Administrator"))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // Check ownership for non-admin users
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (userId != null && resource.AppUserId == userId)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
