using System;
using System.Threading.Tasks;

namespace App.Repository.Interfaces
{
    public interface IUnitOfWork : IDisposable
    {
        Task<bool> Commit();
        IRepository<TEntity> Repository<TEntity>() where TEntity : class;
    }
}
