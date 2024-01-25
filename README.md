[![NuGet](https://buildstats.info/nuget/GlitchedPolygons.Services.JwtService)](https://www.nuget.org/packages/GlitchedPolygons.Services.JwtService)
[![API Docs](https://img.shields.io/badge/api-docs-informational)](https://glitchedpolygons.github.io/JwtService/api/GlitchedPolygons.Services.JwtService.html)
[![Build status](https://ci.appveyor.com/api/projects/status/dr9ak7l95nl9pk6k?svg=true)](https://ci.appveyor.com/project/GlitchedPolygons/jwtservice)

# JWT service

JwtService is a useful service class that provides functionality for generating and validating JWTs.
Can be used in [ASP.NET Core](https://docs.microsoft.com/en-us/aspnet/core/?view=aspnetcore-2.1) apps using the included dependency injection container (under _Startup.cs_ call `services.AddSingleton` and register the service into the DI container).

This library is built as a **netstandard2.0** class library and available through [NuGet](https://www.nuget.org/packages/GlitchedPolygons.Services.JwtService).

## Dependencies

* [Microsoft.IdentityModel.Tokens v5.5.0](https://www.nuget.org/packages/Microsoft.IdentityModel.Tokens/)
* [System.IdentityModel.Tokens.Jwt v5.5.0](https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/)
* xunit NuGet packages (for unit testing only).
