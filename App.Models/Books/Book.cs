using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace App.Models
{
    public class Book
    {
        [BsonId]
        public ObjectId Id { get; set; }

        [BsonElement("Name")]
        public string Name { get; set; }

        [BsonElement("WritterName")]
        public string WritterName { get; set; }

        [BsonElement("Price")]
        public decimal? Price { get; set; }
    }
}
