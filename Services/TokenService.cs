using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthenticationRefreshTokens.Models;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationRefreshTokens.Services
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;


        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public string CreateAccessToken(ApplicationUser user, IList<string> roles)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["SecurityKey"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Name, user.UserName ?? ""),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["AccessTokenExpirationMinutes"])),
                signingCredentials: creds
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        public RefreshToken CreateRefreshToken(string ipAddress)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var randomBytes = new byte[64];
            using var rg = RandomNumberGenerator.Create();
            rg.GetBytes(randomBytes);

            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomBytes),
                Expires = DateTime.UtcNow.AddDays(Convert.ToDouble(jwtSettings["RefreshTokenExpirationDays"])),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };
        }
    }
}