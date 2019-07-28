using MongoDB.Driver;
using App.Repository.Interfaces;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using ServiceStack;
using System.Linq;

namespace App.Repository.Repository
{
    public class BaseRepository<TEntity> : IRepository<TEntity> where TEntity : class
    {
        protected readonly IMongoContext _context;
        protected readonly IMongoCollection<TEntity> DbSet;

        public BaseRepository(IMongoContext context)
        {
            _context = context;
            DbSet = _context.GetCollection<TEntity>(typeof(TEntity).Name);
        }

        public virtual void Add(TEntity obj)
        {
            _context.AddCommand(() => DbSet.InsertOneAsync(obj));
        }

        public virtual async Task<TEntity> GetById(Guid id)
        {
            var data = await DbSet.FindAsync(Builders<TEntity>.Filter.Eq("_id", id));
            return data.SingleOrDefault();
        }

        public virtual async Task<List<TEntity>> GetAll()
        {
            var all = DbSet.Find(Builders<TEntity>.Filter.Empty).Limit(10);
            return await all.ToListAsync();
        }

        public virtual void Update(TEntity obj)
        {
            _context.AddCommand(() => DbSet.ReplaceOneAsync(Builders<TEntity>.Filter.Eq("_id", obj.GetId()), obj));
        }

        public virtual void Remove(Guid id) => _context.AddCommand(() => DbSet.DeleteOneAsync(Builders<TEntity>.Filter.Eq("_id", id)));

        public void Dispose()
        {
            _context?.Dispose();
        }
    }
}
