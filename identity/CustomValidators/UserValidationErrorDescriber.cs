using Microsoft.AspNetCore.Identity;

namespace identity.CustomValidators;

public class UserValidationErrorDescriber : IdentityErrorDescriber
{
    public override IdentityError DefaultError()
    {
        return new IdentityError
        {
            Code = nameof(DefaultError),
            Description = $"An unknown failure has occurred."
        };
    }
    public override IdentityError InvalidUserName(string userName)
        {
            return new IdentityError
            {
                Code = nameof(InvalidUserName),
                Description = $"Username '{userName}' is invalid, can only contain letters or digits."
            };
        }

        public override IdentityError InvalidEmail(string email)
        {
            return new IdentityError
            {
                Code = nameof(InvalidEmail),
                Description = $"Email '{email}' is invalid."
            };
        }

        public override IdentityError DuplicateUserName(string userName)
        {
            return new IdentityError
            {
                Code = nameof(DuplicateUserName),
                Description = $"Username '{userName}' is already taken."
            };
        }

        public override IdentityError DuplicateEmail(string email)
        {
            return new IdentityError
            {
                Code = nameof(DuplicateEmail),
                Description = $"Email '{email}' is already taken."
            };
        }

        public override IdentityError PasswordTooShort(int length)
        {
            return new IdentityError
            {
                Code = nameof(PasswordTooShort),
                Description = $"Passwords must be at least {length} characters."
            };
        }

        public override IdentityError PasswordRequiresNonAlphanumeric()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresNonAlphanumeric),
                Description = $"Passwords must have at least one non alphanumeric character."
            };
        }

        public override IdentityError PasswordRequiresDigit()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresDigit),
                Description = $"Passwords must have at least one digit ('0'-'9')."
            };
        }

        public override IdentityError PasswordRequiresLower()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresLower),
                Description = $"Passwords must have at least one lowercase ('a'-'z')."
            };
        }

        public override IdentityError PasswordRequiresUpper()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresUpper),
                Description = $"Passwords must have at least one uppercase ('A'-'Z')."
            };
        }

        public IdentityError DuplicatePhoneNumber(string phoneNumber)
        {
            return new IdentityError
            {
                Code = nameof(DuplicatePhoneNumber),
                Description = $"Phone number '{phoneNumber}' is already taken."
            };
        }

        public IdentityError InvalidPhoneNumber(string phoneNumber)
        {
            return new IdentityError
            {
                Code = nameof(InvalidPhoneNumber),
                Description = $"Phone number '{phoneNumber}' is invalid."
            };
        }

        public IdentityError EmailRequired()
        {
            return new IdentityError
            {
                Code = nameof(EmailRequired),
                Description = $"Email is required."
            };
        }

        public IdentityError PhoneNumberRequired()
        {
            return new IdentityError
            {
                Code = nameof(PhoneNumberRequired),
                Description = $"Phone number is required."
            };
        }

        public IdentityError RestrictedUsername(IEnumerable<string> matches)
        {
            return new IdentityError
            {
                Code = nameof(RestrictedUsername),
                Description = $"Username must not contain restricted strings: {string.Join(", ", matches)}."
            };
        }
}