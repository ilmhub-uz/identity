using System.ComponentModel.DataAnnotations;
using identity.Entity;
using identity.Services;
using Microsoft.AspNetCore.Identity;

namespace identity.CustomValidators;

public class UserValidator : IUserValidator<User>
{
    public UserValidator(IdentityErrorDescriber errors = null)
    {
        var cast = errors as UserValidationErrorDescriber;
        Describer = cast ?? new UserValidationErrorDescriber();
    }

    public UserValidationErrorDescriber Describer { get; private set; }

    public async Task<IdentityResult> ValidateAsync(UserManager<User> manager, User user)
    {
        var cast = manager as UserManager<User>;
        if(cast != null)
        {
            throw new InvalidCastException($"{nameof(manager)} is not a {typeof(UserManager<User>).FullName}");
        }
        
        var errors = new List<IdentityError>();

        var email = await manager.GetEmailAsync(user);
        var phoneNumber = await manager.GetPhoneNumberAsync(user);
        bool isEmailExists = !string.IsNullOrWhiteSpace(email);
        bool isPhoneNumberExists = !string.IsNullOrWhiteSpace(phoneNumber);

        if(isEmailExists)
        {
            await ValidateEmailAsync(cast, user, errors);
        }
        else
        {
            errors.Add(Describer.EmailRequired());
        }

        if(isPhoneNumberExists)
        {
            await ValidatePhoneNumberAsync(cast, user, errors);
        }

        return errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed(errors.ToArray());
    }

    private async Task ValidatePhoneNumberAsync(UserManager<User> manager, User user, List<IdentityError> errors)
    {
        var phoneNumber = await manager.GetPhoneNumberAsync(user);
        if (string.IsNullOrWhiteSpace(phoneNumber))
        {
            errors.Add(Describer.InvalidPhoneNumber(phoneNumber));
            return;
        }

        if (!new CustomPhoneAttribute().IsValid(phoneNumber))
        {
            errors.Add(Describer.InvalidPhoneNumber(phoneNumber));
            return;
        }

        var owner = manager.Users.FirstOrDefault(x => x.PhoneNumber == phoneNumber);
        if (owner != null &&
            !string.Equals(await manager.GetUserIdAsync(owner), await manager.GetUserIdAsync(user)))
        {
            errors.Add(Describer.DuplicatePhoneNumber(phoneNumber));
        }
    }

    private async Task ValidateEmailAsync(UserManager<User> manager, User user, List<IdentityError> errors)
    {
        var email = await manager.GetEmailAsync(user);
        if (string.IsNullOrWhiteSpace(email))
        {
            errors.Add(Describer.InvalidEmail(email));
            return;
        }
        if (!new EmailAddressAttribute().IsValid(email))
        {
            errors.Add(Describer.InvalidEmail(email));
            return;
        }
        var owner = await manager.FindByEmailAsync(email);
        if (owner != null &&
            !string.Equals(await manager.GetUserIdAsync(owner), await manager.GetUserIdAsync(user)))
        {
            errors.Add(Describer.DuplicateEmail(email));
        }
    }
}