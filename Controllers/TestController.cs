namespace AuthenticationRefreshTokens.Controllers
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;

    [ApiController]
    [Route("api/[controller]")]
    public class TestController : ControllerBase
    {
        [HttpGet("public")]
        public IActionResult Public()
        {
            return Ok("Hello from a public endpoint!");
        }

        [Authorize]
        [HttpGet("protected")]
        public IActionResult Protected()
        {
            return Ok("Hello from a protected endpoint. You are authenticated!");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public IActionResult Admin()
        {
            return Ok("Hello from an admin endpoint. You are an admin!");
        }
    }
}