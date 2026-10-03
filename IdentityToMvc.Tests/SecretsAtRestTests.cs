using IdentityToMvc.Tests.Infrastructure;
using IdentityToMvc.Web.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityToMvc.Tests;

/// <summary>A stolen copy of the database must not contain usable 2FA secrets.</summary>
public class SecretsAtRestTests : IClassFixture<TestAppFactory>
{
    private readonly TestAppFactory _factory;

    public SecretsAtRestTests(TestAppFactory factory) => _factory = factory;

    private async Task<(IServiceScope Scope, UserManager<IdentityUser> Users, ApplicationDbContext Db, IdentityUser User)> NewUserAsync()
    {
        var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var email = $"secret-{Guid.NewGuid():N}@example.test";
        var user = new IdentityUser { UserName = email, Email = email, EmailConfirmed = true };
        Assert.True((await users.CreateAsync(user, TestBrowser.StrongPassword)).Succeeded);
        return (scope, users, scope.ServiceProvider.GetRequiredService<ApplicationDbContext>(), user);
    }

    private static Task<string?> RawTokenAsync(ApplicationDbContext db, IdentityUser user, string name) =>
        db.UserTokens.AsNoTracking()
            .Where(t => t.UserId == user.Id && t.Name == name)
            .Select(t => t.Value)
            .SingleOrDefaultAsync();

    [Fact]
    public async Task Authenticator_key_is_encrypted_in_the_database()
    {
        var (scope, users, db, user) = await NewUserAsync();
        using var _ = scope;

        await users.ResetAuthenticatorKeyAsync(user);
        var key = await users.GetAuthenticatorKeyAsync(user);

        var stored = await RawTokenAsync(db, user, "AuthenticatorKey");
        Assert.NotNull(key);
        Assert.StartsWith("enc:", stored);
        Assert.DoesNotContain(key!, stored);
    }

    [Fact]
    public async Task Recovery_codes_are_hashed_and_work_only_once()
    {
        var (scope, users, db, user) = await NewUserAsync();
        using var _ = scope;

        var codes = (await users.GenerateNewTwoFactorRecoveryCodesAsync(user, 10))!.ToList();

        var stored = await RawTokenAsync(db, user, "RecoveryCodes");
        Assert.All(stored!.Split(';'), entry => Assert.StartsWith("h1:", entry));
        Assert.All(codes, code => Assert.DoesNotContain(code, stored));

        Assert.True((await users.RedeemTwoFactorRecoveryCodeAsync(user, codes[0])).Succeeded);
        Assert.False((await users.RedeemTwoFactorRecoveryCodeAsync(user, codes[0])).Succeeded);
        Assert.Equal(9, await users.CountRecoveryCodesAsync(user));
    }
}
