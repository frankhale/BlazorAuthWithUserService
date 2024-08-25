using Common;
using System.Security.Claims;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;

namespace BlazorCookieAuth.Client
{
    internal class PersistentAuthenticationStateProvider : AuthenticationStateProvider
    {
        private static readonly Task<AuthenticationState> DefaultUnauthenticatedTask =
            Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

        private readonly Task<AuthenticationState> _authenticationStateTask = DefaultUnauthenticatedTask;

        public PersistentAuthenticationStateProvider(PersistentComponentState state)
        {
            if (!state.TryTakeFromJson<UserInfo>(nameof(UserInfo), out var userInfo) || userInfo is null)
            {
                return;
            }

            _authenticationStateTask = Task.FromResult(
                new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(userInfo.Claims(),
                    authenticationType: nameof(PersistentAuthenticationStateProvider)))));
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync() => _authenticationStateTask;
    }
}
