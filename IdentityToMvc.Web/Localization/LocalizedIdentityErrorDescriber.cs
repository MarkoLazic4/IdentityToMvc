using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Localization;

namespace IdentityToMvc.Web.Localization
{
    /// <summary>Translates the validation errors produced by ASP.NET Core Identity.</summary>
    public sealed class LocalizedIdentityErrorDescriber : IdentityErrorDescriber
    {
        private readonly IStringLocalizer<SharedResource> _t;

        public LocalizedIdentityErrorDescriber(IStringLocalizer<SharedResource> localizer)
        {
            _t = localizer;
        }

        private IdentityError Error(string code, string message) => new() { Code = code, Description = message };

        public override IdentityError DefaultError() => Error(nameof(DefaultError), _t["An unknown failure has occurred."]);
        public override IdentityError ConcurrencyFailure() => Error(nameof(ConcurrencyFailure), _t["Optimistic concurrency failure, object has been modified."]);
        public override IdentityError PasswordMismatch() => Error(nameof(PasswordMismatch), _t["Incorrect password."]);
        public override IdentityError InvalidToken() => Error(nameof(InvalidToken), _t["Invalid token."]);
        public override IdentityError RecoveryCodeRedemptionFailed() => Error(nameof(RecoveryCodeRedemptionFailed), _t["Recovery code redemption failed."]);
        public override IdentityError LoginAlreadyAssociated() => Error(nameof(LoginAlreadyAssociated), _t["A user with this login already exists."]);
        public override IdentityError InvalidUserName(string? userName) => Error(nameof(InvalidUserName), _t["Username '{0}' is invalid, can only contain letters or digits.", userName ?? string.Empty]);
        public override IdentityError InvalidEmail(string? email) => Error(nameof(InvalidEmail), _t["Email '{0}' is invalid.", email ?? string.Empty]);
        public override IdentityError DuplicateUserName(string userName) => Error(nameof(DuplicateUserName), _t["Username '{0}' is already taken.", userName]);
        public override IdentityError DuplicateEmail(string email) => Error(nameof(DuplicateEmail), _t["Email '{0}' is already taken.", email]);
        public override IdentityError InvalidRoleName(string? role) => Error(nameof(InvalidRoleName), _t["Role name '{0}' is invalid.", role ?? string.Empty]);
        public override IdentityError DuplicateRoleName(string role) => Error(nameof(DuplicateRoleName), _t["Role name '{0}' is already taken.", role]);
        public override IdentityError UserAlreadyHasPassword() => Error(nameof(UserAlreadyHasPassword), _t["User already has a password set."]);
        public override IdentityError UserLockoutNotEnabled() => Error(nameof(UserLockoutNotEnabled), _t["Lockout is not enabled for this user."]);
        public override IdentityError UserAlreadyInRole(string role) => Error(nameof(UserAlreadyInRole), _t["User already in role '{0}'.", role]);
        public override IdentityError UserNotInRole(string role) => Error(nameof(UserNotInRole), _t["User is not in role '{0}'.", role]);
        public override IdentityError PasswordTooShort(int length) => Error(nameof(PasswordTooShort), _t["Passwords must be at least {0} characters.", length]);
        public override IdentityError PasswordRequiresUniqueChars(int uniqueChars) => Error(nameof(PasswordRequiresUniqueChars), _t["Passwords must use at least {0} different characters.", uniqueChars]);
        public override IdentityError PasswordRequiresNonAlphanumeric() => Error(nameof(PasswordRequiresNonAlphanumeric), _t["Passwords must have at least one non alphanumeric character."]);
        public override IdentityError PasswordRequiresDigit() => Error(nameof(PasswordRequiresDigit), _t["Passwords must have at least one digit ('0'-'9')."]);
        public override IdentityError PasswordRequiresLower() => Error(nameof(PasswordRequiresLower), _t["Passwords must have at least one lowercase ('a'-'z')."]);
        public override IdentityError PasswordRequiresUpper() => Error(nameof(PasswordRequiresUpper), _t["Passwords must have at least one uppercase ('A'-'Z')."]);
    }
}
