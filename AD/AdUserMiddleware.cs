using System.Text;
using System.Threading.Tasks;
using IDMAPI.DAL;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace IDMAPI.Identity
{
    public class AdUserMiddleware
    {
        private readonly RequestDelegate next;

        public AdUserMiddleware(RequestDelegate next)
        {
            this.next = next;
        }

        public async Task Invoke(HttpContext context, IUserProvider userProvider, IConfiguration config, SpuContext spucontext)
        {
            //if (!(userProvider.Initialized))
            //{
            //    //await userProvider.Create(context, config, spucontext);
            //}

            await next(context);
        }
    }
}