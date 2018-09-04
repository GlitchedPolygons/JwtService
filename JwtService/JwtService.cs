using System;
using System.Text;
using System.Security;
using System.Security.Claims;
using System.Security.Principal;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

using Microsoft.IdentityModel.Tokens;

namespace GlitchedPolygons.Services.JwtService
{
    /// <summary>
    /// Useful JWT service for generating and validating tokens.
    /// </summary>
    public class JwtService
    {
        readonly SigningCredentials credentials;
        readonly TokenValidationParameters validationParameters;
        readonly JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

        /// <summary>
        /// Constructs a new <see cref="JwtService"/> instance used for generating and validating tokens using the specified settings.
        /// </summary>
        /// <param name="key">The private key used for generating (and validating) tokens. DO NOT store this anywhere inside your source code/repo! Use a decent secret managing tool instead.</param>
        /// <param name="issuers">The list of valid issuers. Can be left out <c>null</c> (any issuer is valid in that case).</param>
        /// <param name="audiences">The list of valid audiences. Can be left out <c>null</c> (any audience is valid in that case).</param>
        /// <param name="validateLifetime">Should the tokens be validated against their expiration date too? If <c>false</c>, tokens that are already expired WILL validate nonetheless by default with this <see cref="JwtService"/> instance.</param>
        /// <param name="clockSkew">The clock skew to apply (default is 3 minutes).</param>
        public JwtService(SecureString key, IEnumerable<string> issuers = null, IEnumerable<string> audiences = null, bool validateLifetime = true, TimeSpan? clockSkew = null)
        {
            if (key is null || key.Length == 0)
            {
                throw new ArgumentException($"{nameof(JwtService)}::ctor: The mandatory {nameof(key)} parameter is either null or empty!");
            }
            
            validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key.ToString())),
                ClockSkew = clockSkew ?? TimeSpan.FromMinutes(3),
                ValidIssuers = issuers,
                ValidAudiences = audiences,
                ValidateIssuer = issuers != null,
                ValidateAudience = audiences != null,
                ValidateLifetime = validateLifetime
            };

            credentials = new SigningCredentials(validationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha512);

            key.Dispose();
        }

        /// <summary>
        /// Generates and returns a fresh JWT.<para> </para>
        /// If you want the token to expire, set the <paramref name="lifetime"/> parameter to anything not <c>null</c>.<para> </para>
        /// You can also generate a token that will only be valid in the future: use the <paramref name="notBefore"/> parameter for this (make sure it is later than <c>DateTime.UtcNow</c>).
        /// </summary>
        /// <param name="lifetime">The maximum lifetime of this token. Recommended value is around 15 minutes (<c>TimeSpan.FromMinutes(15)</c>).</param>
        /// <param name="notBefore">If not <c>null</c>, the generated token will only be valid from this <see cref="DateTime"/> on.</param>
        /// <param name="issuer">Optional issuer claim.</param>
        /// <param name="audience">Optional audience claim.</param>
        /// <param name="claims">Any additional custom claims.</param>
        /// <returns>The generated JWT in its final, encoded state.</returns>
        public string GenerateToken(TimeSpan? lifetime = null, DateTime? notBefore = null, string issuer = null, string audience = null, IEnumerable<Claim> claims = null)
        {
            DateTime? expires = null;
            if (lifetime.HasValue)
            {
                expires = DateTime.UtcNow.Add(lifetime.Value);
            }

            var jwt = new JwtSecurityToken(
                signingCredentials: credentials,
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: expires,
                notBefore: notBefore ?? DateTime.UtcNow.Subtract(TimeSpan.FromHours(3))
            );

            return jwtSecurityTokenHandler.WriteToken(jwt);
        }

        /// <summary>
        /// Validates a jwt <c>string</c> that has been created using the <see cref="GenerateToken"/> method.<para> </para>
        /// If the validation was successful, a <see cref="Tuple"/> containing both the raw, validated <see cref="JwtSecurityToken"/> and the deserialized <see cref="IPrincipal"/> instance is returned.<para> </para>
        /// If anything went wrong though (invalid, expired, etc...), <c>null</c> is returned.
        /// </summary>
        /// <param name="jwt">The token to validate (encoded jwt).</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> to use for validation: can be left out <c>null</c> (the parameters defined in the <see cref="JwtService"/> constructor are used in that case).</param>
        /// <returns>If validation failed (e.g. expired), <c>null</c>. Otherwise a <see cref="Tuple{JwtSecurityToken, IPrincipal}"/> containing both the raw, validated <see cref="JwtSecurityToken"/> and the deserialized <see cref="IPrincipal"/> instance.</returns>
        public Tuple<JwtSecurityToken, IPrincipal> Validate(string jwt, TokenValidationParameters validationParameters = null)
        {
            try
            {
                var claimsPrincipal = jwtSecurityTokenHandler.ValidateToken(jwt, validationParameters ?? this.validationParameters, out var validatedToken);
                return new Tuple<JwtSecurityToken, IPrincipal>((JwtSecurityToken)validatedToken, claimsPrincipal);
            }
            catch (SecurityTokenExpiredException e) // TODO: find a way to accept some sort of error logging interface
            {
                //logger?.Log(LogLevel.Error, $"{nameof(JwtService)}::{nameof(Validate)}: The token expired and failed validation: {e.Message}", e);
                return null;
            }
            catch (SecurityTokenValidationException e)
            {
                //logger?.Log(LogLevel.Error, $"{nameof(JwtService)}::{nameof(Validate)}: The token was not well-formed or was invalid for some other reason: {e.Message}", e);
                return null;
            }
            catch (Exception e)
            {
                //logger?.Log(LogLevel.Error, $"{nameof(JwtService)}::{nameof(Validate)}: Token failed validation... Error message: {e.Message}", e);
                return null;
            }
        }
    }
}
