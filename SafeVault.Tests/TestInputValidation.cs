using SafeVault.Utilities;

namespace SafeVault.Tests;

// Stress tests for SafeVault input validation (Activity 1).
//
// These tests define the CONTRACT your ValidationHelpers must satisfy.
// Implement the following static methods to make them pass:
//
//   bool   ValidationHelpers.IsValidUsername(string? username)
//   bool   ValidationHelpers.IsValidEmail(string? email)
//   string ValidationHelpers.Sanitize(string? input)
//
// Intent:
//   - IsValidUsername: accept ordinary usernames (letters/digits/_/-),
//     reject null/empty/whitespace and anything containing characters used
//     in SQL injection (' ; -- =) or XSS (< > / script).
//   - IsValidEmail: accept well-formed addresses, reject malformed ones and
//     any address carrying injection/script payloads.
//   - Sanitize: HTML-encode output so injected markup can never execute when
//     rendered (defense in depth on top of Razor's auto-encoding).

public class TestInputValidation
{
    // ---------- Username: positive cases ----------

    [Theory]
    [InlineData("john_doe")]
    [InlineData("Alice123")]
    [InlineData("bob-smith")]
    [InlineData("User42")]
    public void IsValidUsername_AcceptsCleanInput(string username)
    {
        Assert.True(ValidationHelpers.IsValidUsername(username));
    }

    // ---------- Username: SQL injection payloads must be rejected ----------

    [Theory]
    [InlineData("' OR '1'='1")]
    [InlineData("'; DROP TABLE Users;--")]
    [InlineData("admin'--")]
    [InlineData("1=1")]
    [InlineData("' OR 1=1 --")]
    [InlineData("Robert'); DROP TABLE Users;--")]
    public void IsValidUsername_RejectsSqlInjection(string payload)
    {
        Assert.False(ValidationHelpers.IsValidUsername(payload));
    }

    // ---------- Username: XSS payloads must be rejected ----------

    [Theory]
    [InlineData("<script>alert('xss')</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("javascript:alert(1)")]
    [InlineData("<b>bold</b>")]
    [InlineData("\"><svg/onload=alert(1)>")]
    public void IsValidUsername_RejectsXss(string payload)
    {
        Assert.False(ValidationHelpers.IsValidUsername(payload));
    }

    // ---------- Username: empty / null / whitespace must be rejected ----------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsValidUsername_RejectsEmptyOrNull(string? username)
    {
        Assert.False(ValidationHelpers.IsValidUsername(username));
    }

    // ---------- Email: positive cases ----------

    [Theory]
    [InlineData("first.last@sub.domain.org")]
    [InlineData("name+tag@example.co.uk")]
    public void IsValidEmail_AcceptsWellFormedAddresses(string email)
    {
        Assert.True(ValidationHelpers.IsValidEmail(email));
    }

    // ---------- Email: malformed / malicious must be rejected ----------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-email")]
    [InlineData("user@")]
    [InlineData("@example.com")]
    [InlineData("user@@example.com")]
    [InlineData("user name@example.com")]
    [InlineData("<script>@example.com")]
    [InlineData("user@example.com'; DROP TABLE Users;--")]
    [InlineData("\"><script>alert(1)</script>@x.com")]
    public void IsValidEmail_RejectsMalformedOrMalicious(string? email)
    {
        Assert.False(ValidationHelpers.IsValidEmail(email));
    }

    // ---------- Sanitize: output must never carry executable markup ----------

    [Theory]
    [InlineData("<script>alert('xss')</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("\"><svg/onload=alert(1)>")]
    public void Sanitize_EncodesDangerousMarkup(string payload)
    {
        var result = ValidationHelpers.Sanitize(payload);

        // No raw angle brackets should survive — they must be HTML-encoded.
        Assert.DoesNotContain("<", result);
        Assert.DoesNotContain(">", result);
        Assert.Contains("&lt;", result);
    }

    [Fact]
    public void Sanitize_LeavesPlainTextReadable()
    {
        var result = ValidationHelpers.Sanitize("Hello World");
        Assert.Equal("Hello World", result);
    }

    [Fact]
    public void Sanitize_HandlesNullSafely()
    {
        var result = ValidationHelpers.Sanitize(null);
        Assert.Equal(string.Empty, result);
    }
}
