using AspNetCore.Identity.Mongo.Collections;
using AspNetCore.Identity.Mongo.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;
using WebApp.Identity;

namespace WebApp.Controllers
{
    public class UserController : Controller
    {
        private readonly RoleManager<MongoRole> RoleManager;
        private readonly UserManager<ApplicationUser> UserManager;
        private readonly SignInManager<ApplicationUser> SignInManager;
        public IIdentityUserCollection<ApplicationUser> UserCollection;
        public UserController(RoleManager<MongoRole> _roleManager, UserManager<ApplicationUser> _UserManager, SignInManager<ApplicationUser> _SignInManager, IIdentityUserCollection<ApplicationUser> _identityUserCollection)
        {
            RoleManager = _roleManager;
            UserManager = _UserManager;
            SignInManager = _SignInManager;
            UserCollection = _identityUserCollection;
        }
        public IActionResult Index()
        {
            return View(UserManager.Users.ToList());
        }
        public ActionResult ViewUser(string id)
        {
            return View(UserManager.Users);
        }

        public async Task<ActionResult> AddToRole(string roleName, string userName)
        {
            ApplicationUser u = await UserManager.FindByNameAsync(userName);

            if (!await RoleManager.RoleExistsAsync(roleName))
            {
                await RoleManager.CreateAsync(new MongoRole(roleName));
            }

            if (u == null)
            {
                return NotFound();
            }

            await UserManager.AddToRoleAsync(u, roleName);

            return Redirect($"/user/edit/{userName}");
        }
        public async Task<ActionResult> Edit(string id)
        {
            ApplicationUser user = await UserManager.FindByNameAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(ApplicationUser user)
        {
            await UserCollection.UpdateAsync(user);
            return Redirect("/user");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(string id)
        {
            ApplicationUser user = await UserCollection.FindByIdAsync(id);
            await UserCollection.DeleteAsync(user);
            return Redirect("/user");
        }
    }
}