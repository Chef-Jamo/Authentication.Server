using Auth.Service.Project.Validators;
using Xunit;
using FluentAssertions;

namespace Auth.Service.Project.Tests.Validators;

public class TestPasswordDebug
{
    [Fact]
    public void Debug_StrongPasswordAttribute()
    {
        var attribute = new StrongPasswordAttribute();
        
        // Test a simple valid password
        var result1 = attribute.IsValid("MyStr0ngP@55w0rd!");
        Assert.True(result1, $"Password should be valid. Error: {attribute.ErrorMessage}");
        
        var result2 = attribute.IsValid("UltraSecureP@55w0rd9!");
        Assert.True(result2, $"Password should be valid. Error: {attribute.ErrorMessage}");
    }
}