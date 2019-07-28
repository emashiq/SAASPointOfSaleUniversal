using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using App.Repository.Interfaces;
using App.Repository.Repository;

namespace App.Repository.UoW
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly IMongoContext _context;
        private IDictionary<Type, object> repositories = new Dictionary<Type, object>();
        public UnitOfWork(IMongoContext context)
        {
            _context = context;
        }

        public IRepository<TEntity> Repository<TEntity>() where TEntity : class
        {
            if (repositories.Keys.Contains(typeof(TEntity)) == true)
                return (BaseRepository<TEntity>)repositories[typeof(TEntity)];
            BaseRepository<TEntity> tRepositoryObject = new BaseRepository<TEntity>(_context);
            repositories.Add(typeof(TEntity), tRepositoryObject);
            return tRepositoryObject;
        }

        public async Task<bool> Commit()
        {
            var changeAmount = await _context.SaveChanges();

            return changeAmount > 0;
        }

        public void Dispose()
        {
            _context.Dispose();
        }
    }
}
