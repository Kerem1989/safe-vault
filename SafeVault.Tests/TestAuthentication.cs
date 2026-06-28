using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Moq;
using SafeVault.Controllers;
using SafeVault.Models;

// Microsoft.AspNetCore.Mvc ALSO defines a SignInResult, so disambiguate the Identity one.
using IdentitySignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace SafeVault.Tests;

// Activity 2 — Authentication tests.
//
// These tests define the CONTRACT the AccountController login/registration flow
// must satisfy. Some intentionally FAIL against the current code (TDD red) — fix
// the controller until they go green.
//
// Contract:
//   - A successful sign-in for ANY valid user (admin or not) is a success:
//     the user must NOT be sent to AccessDenied/Error. Admins land on the
//     Dashboard. (Bug today: a valid non-admin user is wrongly Access-Denied.)
//   - A failed sign-in (wrong password) keeps the user on the login View with a
//     ModelState error — it does not throw the user to a generic Error page.
//   - An unknown username keeps the user on the login View with a generic
//     "Invalid login attempt." error (don't leak which field was wrong, don't
//     redirect to Error).
//   - A structurally invalid username (injection/XSS) is rejected BEFORE any
//     credentials are checked: PasswordSignInAsync must never be called.
//   - Registration assigns the Admin role to @admin.com addresses and the User
//     role to everyone else.
public class TestAuthentication
{
    private static AccountController BuildController(
        out Mock<UserManager<IdentityUser>> userManager,
        out Mock<SignInManager<IdentityUser>> signInManager,
        out Mock<RoleManager<IdentityRole>> roleManager)
    {
        userManager = MockHelpers.MockUserManager<IdentityUser>();
        signInManager = MockHelpers.MockSignInManager(userManager.Object);
        roleManager = MockHelpers.MockRoleManager<IdentityRole>();
        return new AccountController(roleManager.Object, userManager.Object, signInManager.Object);
    }

    // ---------- Login: success paths ----------

    [Fact]
    public async Task Login_ValidAdmin_RedirectsToDashboard()
    {
        var controller = BuildController(out var userManager, out var signInManager, out _);
        var admin = new IdentityUser { UserName = "alice" };

        signInManager
            .Setup(s => s.PasswordSignInAsync("alice", "Correct1!", It.IsAny<bool>(), It.IsAny<bool>()))
            .ReturnsAsync(IdentitySignInResult.Success);
        userManager.Setup(u => u.FindByNameAsync("alice")).ReturnsAsync(admin);
        userManager.Setup(u => u.IsInRoleAsync(admin, "Admin")).ReturnsAsync(true);

        var result = await controller.Login(new LoginViewModel { UserName = "alice", Password = "Correct1!" });

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Dashboard", redirect.ActionName);
    }

    [Fact]
    public async Task Login_ValidNonAdminUser_IsNotAccessDenied()
    {
        // The current bug: a valid non-admin user gets sent to AccessDenied.
        var controller = BuildController(out var userManager, out var signInManager, out _);
        var user = new IdentityUser { UserName = "bob" };

        signInManager
            .Setup(s => s.PasswordSignInAsync("bob", "Correct1!", It.IsAny<bool>(), It.IsAny<bool>()))
            .ReturnsAsync(IdentitySignInResult.Success);
        userManager.Setup(u => u.FindByNameAsync("bob")).ReturnsAsync(user);
        userManager.Setup(u => u.IsInRoleAsync(user, "Admin")).ReturnsAsync(false);

        var result = await controller.Login(new LoginViewModel { UserName = "bob", Password = "Correct1!" });

        // A valid login is a success — it must not be denied or error out.
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.NotEqual("AccessDenied", redirect.ActionName);
        Assert.NotEqual("Error", redirect.ActionName);
    }

    // ---------- Login: failure paths ----------

    [Fact]
    public async Task Login_WrongPassword_ReturnsViewWithError()
    {
        var controller = BuildController(out var userManager, out var signInManager, out _);
        var user = new IdentityUser { UserName = "bob" };

        signInManager
            .Setup(s => s.PasswordSignInAsync("bob", "wrong", It.IsAny<bool>(), It.IsAny<bool>()))
            .ReturnsAsync(IdentitySignInResult.Failed);
        userManager.Setup(u => u.FindByNameAsync("bob")).ReturnsAsync(user);
        userManager.Setup(u => u.IsInRoleAsync(user, "Admin")).ReturnsAsync(false);

        var result = await controller.Login(new LoginViewModel { UserName = "bob", Password = "wrong" });

        Assert.IsType<ViewResult>(result);
        Assert.False(controller.ModelState.IsValid);
    }

    [Fact]
    public async Task Login_UnknownUser_ReturnsViewWithError()
    {
        var controller = BuildController(out var userManager, out var signInManager, out _);

        signInManager
            .Setup(s => s.PasswordSignInAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()))
            .ReturnsAsync(IdentitySignInResult.Failed);
        userManager.Setup(u => u.FindByNameAsync("ghost")).ReturnsAsync((IdentityUser?)null);

        var result = await controller.Login(new LoginViewModel { UserName = "ghost", Password = "whatever" });

        Assert.IsType<ViewResult>(result);
        Assert.False(controller.ModelState.IsValid);
    }

    [Fact]
    public async Task Login_InjectionUsername_NeverChecksCredentials()
    {
        var controller = BuildController(out _, out var signInManager, out _);

        await controller.Login(new LoginViewModel { UserName = "' OR 1=1 --", Password = "x" });

        signInManager.Verify(
            s => s.PasswordSignInAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<bool>()),
            Times.Never);
    }

    // ---------- Registration: role assignment ----------

    [Fact]
    public async Task Register_AdminEmail_AssignsAdminRole()
    {
        var controller = BuildController(out var userManager, out _, out _);

        userManager
            .Setup(u => u.CreateAsync(It.IsAny<IdentityUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);
        userManager
            .Setup(u => u.AddToRoleAsync(It.IsAny<IdentityUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);

        await controller.Register(new User { Name = "boss", Email = "boss@admin.com", Password = "P@ssw0rd!" });

        userManager.Verify(u => u.AddToRoleAsync(It.IsAny<IdentityUser>(), "Admin"), Times.Once);
        userManager.Verify(u => u.AddToRoleAsync(It.IsAny<IdentityUser>(), "User"), Times.Never);
    }

    [Fact]
    public async Task Register_NormalEmail_AssignsUserRole()
    {
        var controller = BuildController(out var userManager, out _, out _);

        userManager
            .Setup(u => u.CreateAsync(It.IsAny<IdentityUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);
        userManager
            .Setup(u => u.AddToRoleAsync(It.IsAny<IdentityUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);

        await controller.Register(new User { Name = "carol", Email = "carol@example.com", Password = "P@ssw0rd!" });

        userManager.Verify(u => u.AddToRoleAsync(It.IsAny<IdentityUser>(), "User"), Times.Once);
        userManager.Verify(u => u.AddToRoleAsync(It.IsAny<IdentityUser>(), "Admin"), Times.Never);
    }
}
