using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using CentraliaStore.Data;
using CentraliaStore.Models;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using CentraliaStore.Authorization;

namespace CentraliaStore.Controllers
{
    [Authorize]
    public class ApiKeysController : Controller
    {
        private readonly StoreContext _context;
        private readonly IAuthorizationService _authorizationService;

        public ApiKeysController(StoreContext context, IAuthorizationService authorizationService)
        {
            _context = context;
            _authorizationService = authorizationService;
        }

        // GET: ApiKeys
        public async Task<IActionResult> Index()
        {
           
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isAdmin = User.IsInRole("Administrator");

            IQueryable<ApiKey> query = _context.ApiKeys.Include(k => k.AppUser);

            if (!isAdmin)
            {
                // Users only see their own keys
                query = query.Where(k => k.AppUserId == userId);
            }

            var apiKeys = await query.ToListAsync();
            return View(apiKeys);
        }

        // GET: ApiKeys/Details/5
        public async Task<IActionResult> Details(int? id)
        {
           
            if (id == null)
                return NotFound();

            var apiKey = await _context.ApiKeys.Include(k => k.AppUser).FirstOrDefaultAsync(k => k.ApiKeyId == id);
            if (apiKey == null)
                return NotFound();

            var authorizationResult = await _authorizationService.AuthorizeAsync(User, apiKey, Operations.Read);
            if (!authorizationResult.Succeeded)
            {
                if (User.Identity.IsAuthenticated)
                    return Forbid();
                else
                    return Challenge();
            }

            return View(apiKey);
        }

        // GET: ApiKeys/Create
        public IActionResult Create()
        {
           
            if (!User.Identity.IsAuthenticated)
                return Challenge();

            if (User.IsInRole("Administrator"))
            {
                ViewBag.AppUsers = new SelectList(_context.Users, "Id", "UserName");
            }


            return View();
        }

        // POST: ApiKeys/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ApiKeyId,ApiSecret, AppUserId")] ApiKey apiKey)
        {

            if (!User.IsInRole("Administrator"))
            {
                apiKey.AppUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            }
            else
            {
                
                var userExists = await _context.Users.AnyAsync(u => u.Id == apiKey.AppUserId);
                if (!userExists)
                {
                    ModelState.AddModelError("AppUserId", "Selected user does not exist.");
                }
            }


            ModelState.Remove(nameof(apiKey.AppUser));
            ModelState.Remove(nameof(apiKey.AppUserId));

            var authorizationResult = await _authorizationService.AuthorizeAsync(User, apiKey, Operations.Create);
            if (!authorizationResult.Succeeded)
            {
                if (User.Identity.IsAuthenticated)
                    return Forbid();
                else
                    return Challenge();
            }

            if (ModelState.IsValid)
            {
                _context.Add(apiKey);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }

            if (User.IsInRole("Administrator"))
            {
                ViewBag.AppUsers = new SelectList(_context.Users, "Id", "UserName");
            }


            return View(apiKey);
        }

        // GET: ApiKeys/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            
            if (id == null)
                return NotFound();

            var apiKey = await _context.ApiKeys.FindAsync(id);
            if (apiKey == null)
                return NotFound();
           
            var authorizationResult = await _authorizationService.AuthorizeAsync(User, apiKey, Operations.Update);
            if (!authorizationResult.Succeeded)
            {
                if (User.Identity.IsAuthenticated)
                    return Forbid();
                else
                    return Challenge();
            }

            return View(apiKey);
        }

       

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ApiKeyId,ApiSecret")] ApiKey apiKey)
        {
            if (id != apiKey.ApiKeyId)
                return NotFound();

            var originalApiKey = await _context.ApiKeys.AsNoTracking().FirstOrDefaultAsync(k => k.ApiKeyId == id);
            if (originalApiKey == null)
                return NotFound();
            ModelState.Remove(nameof(originalApiKey.AppUser));
            ModelState.Remove(nameof(originalApiKey.AppUserId));
            var authorizationResult = await _authorizationService.AuthorizeAsync(User, originalApiKey, Operations.Update);
            if (!authorizationResult.Succeeded)
            {
                if (User.Identity.IsAuthenticated)
                    return Forbid();
                else
                    return Challenge();
            }

            if (ModelState.IsValid)
            {
                try
                {
                   
                    apiKey.AppUserId = originalApiKey.AppUserId;

                    _context.Update(apiKey);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!ApiKeyExists(apiKey.ApiKeyId))
                        return NotFound();
                    else
                        throw;
                }
                return RedirectToAction(nameof(Index));
            }

            return View(apiKey);
        }


        // GET: ApiKeys/Delete/5
        [Authorize(Roles = "Administrator")]
        public async Task<IActionResult> Delete(int? id)
        {

            if (id == null)
                return NotFound();

            
            if (!User.IsInRole("Administrator"))
            {
                if (User.Identity.IsAuthenticated)
                    return Forbid();   
                else
                    return Challenge(); 
            }

            var apiKey = await _context.ApiKeys
                .Include(k => k.AppUser)
                .FirstOrDefaultAsync(k => k.ApiKeyId == id);

            if (apiKey == null)
                return NotFound();

            return View(apiKey);
        }

        // POST: ApiKeys/Delete/5
        [Authorize(Roles = "Administrator")]
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            if (!User.IsInRole("Administrator"))
            {
                if (User.Identity.IsAuthenticated)
                    return Forbid();    
                else
                    return Challenge(); 
            }

            var apiKey = await _context.ApiKeys.FindAsync(id);
            if (apiKey == null)
                return NotFound();

            _context.ApiKeys.Remove(apiKey);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        private bool ApiKeyExists(int id)
        {
            return _context.ApiKeys.Any(e => e.ApiKeyId == id);
        }
    }
}
