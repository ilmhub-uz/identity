using Microsoft.AspNetCore.Identity;

namespace identity.CustomValidators;

public class UserValidatorErrorDescriber : IdentityErrorDescriber
{
    public override IdentityError DefaultError()
    {
        return new IdentityError
        {
            Code = nameof(DefaultError),
            Description = "An unknown failure has occurred."
        };
    }
    public override IdentityError PasswordTooShort(int length)
    {
        return new IdentityError
        {
            Code = nameof(PasswordTooShort),
            Description = $"Passwords must be at least 10000 characters."
        };
    }
}