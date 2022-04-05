using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace identity.Attributes;

public class CustomRequiredAttribute : RequiredAttribute
{
    public override string FormatErrorMessage(string Name)
    {
        return $"{Name} is required";
    }
}

public class CustomPhoneAttribute : RegularExpressionAttribute
{
    public CustomPhoneAttribute() : base(@"^[\+]?(998[-\s\.]?)([0-9]{2}[-\s\.]?)([0-9]{3}[-\s\.]?)([0-9]{2}[-\s\.]?)([0-9]{2}[-\s\.]?)$")
    {
        ErrorMessage = "Invalid phone number";
    }
}

public class CustomEmailAttribute : RegularExpressionAttribute
{
    public CustomEmailAttribute() : base(@"\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*")
    {
        ErrorMessage = "Invalid email address";
    }
}

public class CustomMinLengthAttribute : ValidationAttribute
{
    private readonly int _length;

    public CustomMinLengthAttribute(int length)
    {
        _length = length;
    }

    public override bool IsValid(object value)
    {
        if (value == null)
        {
            return false;
        }

        var valueAsString = value.ToString();

        return valueAsString.Length >= _length;
    }

    public override string FormatErrorMessage(string Name)
    {
        return $"At least {_length} characters";
    }
}

public class CustomMaxLengthAttribute : ValidationAttribute
{
    private readonly int _length;

    public CustomMaxLengthAttribute(int length)
    {
        _length = length;
    }

    public override bool IsValid(object value)
    {
        if (value == null)
        {
            return false;
        }

        var valueAsString = value.ToString();

        return valueAsString.Length <= _length;
    }

    public override string FormatErrorMessage(string Name)
    {
        return $"No more than {_length} characters";
    }
}
public class CustomCompareAttribute : CompareAttribute
{
    public CustomCompareAttribute(string otherProperty)
        : base(otherProperty)
    {
        ErrorMessage = "Password fields must match";
    }
}

public class CustomDisplayNameAttribute : DisplayNameAttribute
{
    private string _key;

    public CustomDisplayNameAttribute(string key)
    {
        _key = key;
    }

    public override string DisplayName
    {
        get
        {
            return _key;
        }
    }
}