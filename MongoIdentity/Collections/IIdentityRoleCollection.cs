using AspNetCore.Identity.Mongo.Model;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AspNetCore.Identity.Mongo.Collections
{
    public interface IIdentityRoleCollection<TRole> where TRole : MongoRole
    {
        Task<TRole> FindByNameAsync(string normalizedName);
        Task<TRole> FindByIdAsync(string roleId);
        Task<IEnumerable<TRole>> GetAllAsync();
        Task<TRole> CreateAsync(TRole obj);
        Task UpdateAsync(TRole obj);
        Task DeleteAsync(TRole obj);
    }
}