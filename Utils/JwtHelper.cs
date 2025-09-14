using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

static class JwtHelper
{
    public static string Issue(string secret, string sub, IEnumerable<string> scopes, TimeSpan ttl)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var now = DateTime.UtcNow;
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, sub) };
        claims.AddRange(scopes.Select(s => new Claim("scope", s)));
        var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            claims: claims, notBefore: now, expires: now.Add(ttl), signingCredentials: creds);
        return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(jwt);
    }
}
