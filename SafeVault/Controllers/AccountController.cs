using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Utilities;

namespace SafeVault.Controllers ;

    public class AccountController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;


        public AccountController(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(User model)
        {
            var result = new IdentityResult();
            if (ModelState.IsValid)
            {
                var user = new IdentityUser { UserName = model.Name, Email = model.Email };
                result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    if (model.Email.EndsWith("@admin.com"))
                    {
                        await _userManager.AddToRoleAsync(user, "Admin");
                    }
                    else
                    {
                        await _userManager.AddToRoleAsync(user, "User");
                    }
                    return RedirectToAction("Index", "Home");
                }
            }
            return RedirectToAction("Error", "Home");
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ValidationHelpers.ValidateInput(model.UserName, model.Password))
            {
                ModelState.AddModelError("", "Invalid username or password.");
                return RedirectToAction("Error", "Home");
            }
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, model.RememberMe,
                    false);
                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user == null)
                {
                    ModelState.AddModelError("", "Invalid login attempt.");
                    return RedirectToAction("Error", "Home");
                }
                
                var roles = GetRoles(_userManager, user);
                    if (result.Succeeded)
                    {
                        if (roles)
                        {
                            return RedirectToAction("Dashboard", "Home");
                        }
                        return RedirectToAction("AccessDenied", "Account");
                    }
                    ModelState.AddModelError("", "Invalid login attempt.");
                }
            return View(model);
        }

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> AccessDenied()
        {
            return View();
        }

        private static bool GetRoles(UserManager<IdentityUser> userManager, IdentityUser user)
        {
            if (userManager.IsInRoleAsync(user, "Admin").Result)
            {
                return true;
            }
            return false;
        }

        [HttpPost]
        public async Task<IActionResult> SetClaims()
        {
            var user = _userManager.GetUserAsync(User).Result;
            await _userManager.AddClaimAsync(user, new Claim("Permission", "CanAccessDashboard"));
            return RedirectToAction("Index", "Home");
        }
    }