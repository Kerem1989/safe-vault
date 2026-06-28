using Microsoft.AspNetCore.Authorization;
using SafeVault.Controllers;

namespace SafeVault.Tests;

// Activity 2 — Authorization (RBAC) tests.
//
// Verifies that role-restricted features are actually protected by an
// [Authorize] policy, so only the right role can reach them. Reflection keeps
// this a fast unit test (no HTTP pipeline required).
//
// Contract:
//   - The Admin Dashboard is protected by the "Admin" authorization policy.
//   - Non-admin features (Index, Privacy) stay publicly reachable.
public class TestAuthorization
{
    private static AuthorizeAttribute? GetAuthorize(string actionName)
    {
        var method = typeof(HomeController).GetMethod(actionName)!;
        return method.GetCustomAttributes(typeof(AuthorizeAttribute), true)
            .Cast<AuthorizeAttribute>()
            .FirstOrDefault();
    }

    [Fact]
    public void Dashboard_RequiresAdminPolicy()
    {
        var authorize = GetAuthorize(nameof(HomeController.Dashboard));

        Assert.NotNull(authorize);
        Assert.Equal("Admin", authorize!.Policy);
    }

    [Theory]
    [InlineData(nameof(HomeController.Index))]
    [InlineData(nameof(HomeController.Privacy))]
    public void PublicPages_AreNotRestricted(string action)
    {
        Assert.Null(GetAuthorize(action));
    }
}
