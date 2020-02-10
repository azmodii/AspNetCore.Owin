using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API
{
    [ApiController]
    public class APIController : ControllerBase
    {
        [Authorize]
        [HttpGet]
        [Route("api/hi")]
        public string Helloworld()
        {
            return "Hello!";
        }
    }
    
}
