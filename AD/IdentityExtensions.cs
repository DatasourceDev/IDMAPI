using System.DirectoryServices.AccountManagement;
using System.Linq;

namespace IDMAPI.Identity.Extensions
{
    public static class IdentityExtensions
    {
        public static IQueryable<UserPrincipal> FilterUsers(this IQueryable<UserPrincipal> principals) =>
            principals.Where(x => x.Guid.HasValue);

        public static IQueryable<AdUser2> SelectAdUsers(this IQueryable<UserPrincipal> principals) =>
            principals.Select(x => AdUser2.CastToAdUser(x));
    }
}