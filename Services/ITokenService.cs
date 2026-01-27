using AuthenticationRefreshTokens.Models;

namespace AuthenticationRefreshTokens.Services
{
    public interface ITokenService
    {
        string CreateAccessToken(ApplicationUser user, IList<string> userRoles);
        RefreshToken CreateRefreshToken(string ipAddress);
    }
}