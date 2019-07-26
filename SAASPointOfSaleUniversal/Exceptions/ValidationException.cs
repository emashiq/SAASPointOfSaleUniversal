using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;

namespace WebApp.Exceptions
{
    public class ValidationException : Exception
    {
        private readonly IEnumerable<IdentityError> errors;

        public ValidationException(IEnumerable<IdentityError> errors) : base(string.Join(" ", errors.Select(x => x.Description)))
        {

        }
    }
}
