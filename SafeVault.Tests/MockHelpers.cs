using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Moq;

namespace SafeVault.Tests;

// ASP.NET Core Identity managers have heavy constructors that are painful to new up
// in a unit test. These factories build loose mocks so the tests can focus on behavior.
internal static class MockHelpers
{
    public static Mock<UserManager<TUser>> MockUserManager<TUser>() where TUser : class
    {
        var store = new Mock<IUserStore<TUser>>();
        var mgr = new Mock<UserManager<TUser>>(
            store.Object, null!, null!, null!, null!, null!, null!, null!, null!);
        mgr.Object.UserValidators.Add(new UserValidator<TUser>());
        mgr.Object.PasswordValidators.Add(new PasswordValidator<TUser>());
        return mgr;
    }

    public static Mock<SignInManager<TUser>> MockSignInManager<TUser>(UserManager<TUser> userManager)
        where TUser : class
    {
        var contextAccessor = new Mock<IHttpContextAccessor>();
        var claimsFactory = new Mock<IUserClaimsPrincipalFactory<TUser>>();
        return new Mock<SignInManager<TUser>>(
            userManager, contextAccessor.Object, claimsFactory.Object, null!, null!, null!, null!);
    }

    public static Mock<RoleManager<TRole>> MockRoleManager<TRole>() where TRole : class
    {
        var store = new Mock<IRoleStore<TRole>>();
        return new Mock<RoleManager<TRole>>(store.Object, null!, null!, null!, null!);
    }
}
