using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using userapp.Models;
using userapp.ViewModels;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Linq;

namespace userapp.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<users> userManager;
        private readonly SignInManager<users> signInManager;
        private readonly RoleManager<IdentityRole> roleManager;

        public AccountController(
            UserManager<users> userManager,
            SignInManager<users> signInManager,
            RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
        }

        // ================= LOGIN =================

        public IActionResult Login(string? role)
        {
            // Pass the requested role to the view so the UI can show role-specific login (or allow switching)
            return View(new ViewModels.LoginViewModel { Role = role });
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await signInManager.PasswordSignInAsync(
                    model.Email,
                    model.Password,
                    model.RememberMe,
                    false);

                if (result.Succeeded)
                {
                    var user = await userManager.FindByEmailAsync(model.Email);

                    // If the login page requested a specific role, ensure the user has that role
                    if (!string.IsNullOrEmpty(model.Role))
                    {
                        if (await userManager.IsInRoleAsync(user, model.Role))
                        {
                            return model.Role switch
                            {
                                "Admin" => RedirectToAction("AdminDashboard", "Admin"),
                                "Storeman" => RedirectToAction("StoreDashboard", "Store"),
                                "Employee" => RedirectToAction("EmployeeDashboard", "Employee"),
                                "Customer" => RedirectToAction("CustomerDashboard", "Customer"),
                                _ => RedirectToAction("Index", "Home"),
                            };
                        }

                        // Signed in but not in requested role -> sign out and show error
                        await signInManager.SignOutAsync();
                        ModelState.AddModelError("", "You are not authorized for the selected role.");
                        return View(model);
                    }

                    // No specific role requested: redirect based on first role match
                    if (await userManager.IsInRoleAsync(user, "Admin"))
                        return RedirectToAction("AdminDashboard", "Admin");

                    if (await userManager.IsInRoleAsync(user, "Storeman"))
                        return RedirectToAction("StoreDashboard", "Store");

                    if (await userManager.IsInRoleAsync(user, "Employee"))
                        return RedirectToAction("EmployeeDashboard", "Employee");

                    if (await userManager.IsInRoleAsync(user, "Customer"))
                        return RedirectToAction("CustomerDashboard", "Customer");

                    return RedirectToAction("Index", "Home");
                }

                ModelState.AddModelError("", "Invalid login attempt");
            }

            return View(model);
        }

        // ================= REGISTER =================

        public async Task<IActionResult> Register()
        {
            // Provide a safe list of roles users can self-register as
            string[] allowedRoles = { "Customer", "Employee", "Storeman" };

            // Ensure allowed roles exist so the dropdown can be populated
            foreach (var r in allowedRoles)
            {
                if (!await roleManager.RoleExistsAsync(r))
                    await roleManager.CreateAsync(new IdentityRole(r));
            }

            var roles = roleManager.Roles
                .Where(r => allowedRoles.Contains(r.Name))
                .Select(r => new SelectListItem { Value = r.Name, Text = r.Name })
                .ToList();

            ViewBag.AvailableRoles = roles;

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                users newUser = new users
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FullName = model.FullName
                };

                var result = await userManager.CreateAsync(newUser, model.Password);

                if (result.Succeeded)
                {
                    // Re-fetch the persisted user and assign selected role (validated below)
                    var createdUser = await userManager.FindByEmailAsync(newUser.Email);

                    if (createdUser != null)
                    {
                        // Only allow safe roles to be self-selected during registration
                        string[] allowedRoles = { "Customer", "Employee", "Storeman" };
                        var roleName = string.IsNullOrEmpty(model.Role) ? "Customer" : model.Role;

                        if (!allowedRoles.Contains(roleName))
                        {
                            ModelState.AddModelError("Role", "The selected role is not allowed.");

                            // repopulate roles for the view
                            ViewBag.AvailableRoles = roleManager.Roles
                                .Where(r => allowedRoles.Contains(r.Name))
                                .Select(r => new SelectListItem { Value = r.Name, Text = r.Name })
                                .ToList();

                            return View(model);
                        }

                        // Ensure the role exists (should already from GET but double-check)
                        if (!await roleManager.RoleExistsAsync(roleName))
                        {
                            var createRoleResult = await roleManager.CreateAsync(new IdentityRole(roleName));
                            if (!createRoleResult.Succeeded)
                            {
                                await userManager.DeleteAsync(createdUser);
                                foreach (var error in createRoleResult.Errors)
                                    ModelState.AddModelError("", error.Description);

                                ViewBag.AvailableRoles = roleManager.Roles
                                    .Where(r => allowedRoles.Contains(r.Name))
                                    .Select(r => new SelectListItem { Value = r.Name, Text = r.Name })
                                    .ToList();

                                return View(model);
                            }
                        }

                        var addRoleResult = await userManager.AddToRoleAsync(createdUser, roleName);

                        if (!addRoleResult.Succeeded)
                        {
                            // If role assignment failed, delete the created user and show errors
                            await userManager.DeleteAsync(createdUser);

                            foreach (var error in addRoleResult.Errors)
                                ModelState.AddModelError("", error.Description);

                            ViewBag.AvailableRoles = roleManager.Roles
                                .Where(r => allowedRoles.Contains(r.Name))
                                .Select(r => new SelectListItem { Value = r.Name, Text = r.Name })
                                .ToList();

                            return View(model);
                        }

                        // Redirect to login and pre-select the role on the login page
                        return RedirectToAction("Login", "Account", new { role = roleName });
                    }

                    ModelState.AddModelError("", "Unable to find created user to assign role.");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            return View(model);
        }

        // ================= VERIFY EMAIL =================

        public IActionResult VerifyEmail()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> VerifyEmail(VerifyEmailViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    ModelState.AddModelError("", "Email not found");
                    return View(model);
                }

                return RedirectToAction("ChangePassword", new { username = user.UserName });
            }

            return View(model);
        }

        // ================= CHANGE PASSWORD =================

        public IActionResult ChangePassword(string username)
        {
            if (string.IsNullOrEmpty(username))
                return RedirectToAction("VerifyEmail");

            return View(new ChangePassswordViewModel { Email = username });
        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePassswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    ModelState.AddModelError("", "Email not found!");
                    return View(model);
                }

                var result = await userManager.RemovePasswordAsync(user);

                if (result.Succeeded)
                {
                    result = await userManager.AddPasswordAsync(user, model.NewPassword);

                    if (result.Succeeded)
                        return RedirectToAction("Login");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            return View(model);
        }

        // ================= LOGOUT =================

        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        // ================= CREATE ROLES (RUN ONCE THEN DELETE) =================

        public async Task<IActionResult> CreateRoles()
        {
            try
            {
                string[] roles = { "Admin", "Storeman", "Employee", "Customer" };

                foreach (var role in roles)
                {
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        await roleManager.CreateAsync(new IdentityRole(role));
                    }
                }

                return Content("Roles created successfully");
            }
            catch (Exception ex)
            {
                return Content("Error: " + ex.Message);
            }
        }
    }
    }
