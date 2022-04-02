using identity.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace identity.CustomValidators;

public class UserValidator : IUserValidator<User>
{

    public UserValidator(IdentityErrorDescriber errors =null)
    {
        var cast = errors as UserValidationErrorDescriber;
        Describer = cast ?? new UserValidationErrorDescriber();
    }
    public Task<IdentityResult> ValidateAsync(UserManager<User> manager, User user)
    {
        throw new NotImplementedException();
    }
    public UserValidationErrorDescriber Describer { get; private set; }

    
}