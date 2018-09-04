[![CircleCI](https://circleci.com/gh/GlitchedPolygons/CompressionUtility/tree/master.svg?style=shield)](https://circleci.com/gh/GlitchedPolygons/CompressionUtility/tree/master)

# JWT service

JwtService is a useful service class that provides functionality for generating and validating JWTs.
Can be used in [ASP.NET Core](https://docs.microsoft.com/en-us/aspnet/core/?view=aspnetcore-2.1) [2.1](https://docs.microsoft.com/en-us/aspnet/core/release-notes/aspnetcore-2.1?view=aspnetcore-2.1) apps using the included dependency injection container (under _Startup.cs_ call `services.AddSingleton` and register the service into the DI container).

This library is built as a **netstandard2.0** class library and available through [NuGet](https://www.nuget.org/packages/GlitchedPolygons.Services.CompressionUtility/1.0.1).

## Dependencies

* [Microsoft.IdentityModel.Tokens v5.2.4](https://www.nuget.org/packages/Microsoft.IdentityModel.Tokens/)
* [System.IdentityModel.Tokens.Jwt v5.2.4](https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/)
* xunit NuGet packages (for unit testing only).
