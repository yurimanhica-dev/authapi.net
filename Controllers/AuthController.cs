using AuthenticationRefreshTokens.DTOs;
using AuthenticationRefreshTokens.Models;
using AuthenticationRefreshTokens.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationRefreshTokens.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ITokenService _tokenService;
        private readonly ApplicationDbContext _context;

        public AuthController(UserManager<ApplicationUser> userManager, ITokenService tokenService, ApplicationDbContext context)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _context = context;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO dto)
        {
            var user = new ApplicationUser
            {
                UserName = dto.Username,
                Email = dto.Email
            };

            var userExists = await _userManager.FindByEmailAsync(dto.Email);
            if (userExists != null)
                return Conflict("User already exists!");

            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            return Ok(new { Message = "User created successfully!" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO dto)
        {
            var user = await _userManager.Users
            .Include(x => x.RefreshTokens)
            .SingleOrDefaultAsync(u => u.Email == dto.Email);

            if (user == null || !await _userManager.CheckPasswordAsync(user, dto.Password))
                return Unauthorized(new { Message = "Invalid email or password." });

            var userRoles = await _userManager.GetRolesAsync(user);
            var accessToken = _tokenService.CreateAccessToken(user, userRoles);
            var refreshToken = _tokenService.CreateRefreshToken(GetIpAddress());

            user.RefreshTokens.Add(refreshToken);
            await _userManager.UpdateAsync(user);
            return Ok(new TokenRequestDTO(accessToken, refreshToken.Token));
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequestDTO dto)
        {
            var refreshToken = dto.RefreshToken;
            var user = await _userManager.Users
                .Include(x => x.RefreshTokens)
                .SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == refreshToken));

            if (user == null)
                return Unauthorized(new { Message = "Invalid refresh token." });

            var existingToken = user.RefreshTokens.Single(t => t.Token == refreshToken);
            if (!existingToken.IsActive)
            {
                return Unauthorized(new { Message = "Refresh token is not active." });
            }

            existingToken.Revoked = DateTime.UtcNow;
            existingToken.RevokedByIp = GetIpAddress();

            var newRefreshToken = _tokenService.CreateRefreshToken(GetIpAddress());
            existingToken.ReplacedByToken = newRefreshToken.Token;
            user.RefreshTokens.Add(newRefreshToken);

            await _userManager.UpdateAsync(user);

            var roles = await _userManager.GetRolesAsync(user);
            var newAccessToken = _tokenService.CreateAccessToken(user, roles);

            return Ok(new TokenRequestDTO(newAccessToken, newRefreshToken.Token));
        }

        [HttpPost("revoke-token")]
        public async Task<IActionResult> RevokeToken([FromBody] TokenRequestDTO dto)
        {
            var token = dto.RefreshToken;
            var user = await _userManager.Users
                .Include(x => x.RefreshTokens)
                .SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));

            if (user == null)
                return NotFound(new { Message = "User not found." });

            var existingToken = user.RefreshTokens.Single(t => t.Token == token);
            if (!existingToken.IsActive)
            {
                return BadRequest(new { Message = "This token is already revoked." });
            }

            existingToken.Revoked = DateTime.UtcNow;
            existingToken.RevokedByIp = GetIpAddress();
            await _userManager.UpdateAsync(user);

            return Ok(new { Message = "Token revoked successfully." });
        }
        private string GetIpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"].ToString();
            else
                return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }
    }
}
