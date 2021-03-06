﻿using System;
using System.Text;
using System.Security.Claims;
using System.Security.Principal;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;

namespace GlitchedPolygons.Services.JwtService
{
    /// <summary>
    /// Useful JWT service for generating and validating tokens.
    /// </summary>
    public class JwtService
    {
        private readonly SigningCredentials credentials;
        private readonly TokenValidationParameters validationParameters;
        private readonly JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

        /// <summary>
        /// Constructs a new <see cref="JwtService"/> instance used for generating and validating tokens using the specified settings. Uses the HMAC-SHA512 algorithm.
        /// </summary>
        /// <param name="key">The private key used for generating (and validating) tokens. DO NOT store this anywhere inside your source code/repo! Use a decent secret managing tool instead.</param>
        /// <param name="issuers">The list of valid issuers. Can be left out <c>null</c> (any issuer is valid in that case).</param>
        /// <param name="audiences">The list of valid audiences. Can be left out <c>null</c> (any audience is valid in that case).</param>
        /// <param name="validateLifetime">Should the tokens be validated against their expiration date too? If <c>false</c>, tokens that are already expired WILL validate nonetheless by default with this <see cref="JwtService"/> instance.</param>
        /// <param name="clockSkew">The clock skew to apply (default is 3 minutes).</param>
        public JwtService(string key, IEnumerable<string> issuers = null, IEnumerable<string> audiences = null, bool validateLifetime = true, TimeSpan? clockSkew = null)
        {
            if (string.IsNullOrEmpty(key))
            {
                throw new ArgumentException($"{nameof(JwtService)}::ctor: The mandatory {nameof(key)} parameter is either null or empty!");
            }

            validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                ClockSkew = clockSkew ?? TimeSpan.FromMinutes(3),
                ValidIssuers = issuers,
                ValidAudiences = audiences,
                ValidateIssuer = issuers != null,
                ValidateAudience = audiences != null,
                ValidateLifetime = validateLifetime
            };

            credentials = new SigningCredentials(validationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha512);
        }

        /// <summary>
        /// Constructs a new <see cref="JwtService"/> instance used for generating/validating tokens asymmetrically using the specified RSA key and token settings.
        /// </summary>
        /// <param name="rsaKey">If this <see cref="JwtService"/> instance is meant to generate new tokens, this must be the private RSA key, because that's needed for signing JWTs.<para> </para>If you're only validating tokens though, well then you can pass the public key here.</param>
        /// <param name="issuers">The list of valid issuers. Can be left out <c>null</c> (any issuer would be valid in that case).</param>
        /// <param name="audiences">The list of valid audiences. Can be left out <c>null</c> (any audience is valid in that case).</param>
        /// <param name="validateLifetime">Should the tokens be validated against their expiration date too? If <c>false</c>, tokens that are already expired WILL validate nonetheless by default with this <see cref="JwtService"/> instance.</param>
        /// <param name="clockSkew">The clock skew to apply (default is 3 minutes).</param>
        public JwtService(RSAParameters rsaKey, IEnumerable<string> issuers = null, IEnumerable<string> audiences = null, bool validateLifetime = true, TimeSpan? clockSkew = null)
        {
            validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new RsaSecurityKey(rsaKey),
                ClockSkew = clockSkew ?? TimeSpan.FromMinutes(3),
                ValidIssuers = issuers,
                ValidAudiences = audiences,
                ValidateIssuer = issuers != null,
                ValidateAudience = audiences != null,
                ValidateLifetime = validateLifetime
            };

            string algo;
            switch (validationParameters.IssuerSigningKey.KeySize)
            {
                case 2048:
                    algo = SecurityAlgorithms.RsaSha256;
                    break;
                case 3072:
                    algo = SecurityAlgorithms.RsaSha384;
                    break;
                case 4096:
                    algo = SecurityAlgorithms.RsaSha512;
                    break;
                default:
                    throw new ArgumentException($"{nameof(JwtService)}::Ctor: The {nameof(rsaKey)} you provided is not of the size 2048, 3072 or 4096. Only these three key sizes are supported!");
            }

            credentials = new SigningCredentials(validationParameters.IssuerSigningKey, algo);
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

            if (notBefore.HasValue && notBefore.Value.Kind != DateTimeKind.Utc)
            {
                throw new ArgumentException($"{nameof(JwtService)}::{nameof(GenerateToken)}: The {notBefore} parameter is not in UTC! Make sure it is!!");
            }

            // Ensure that the provided RSA key is the private key.
            var rsaKey = validationParameters?.IssuerSigningKey as RsaSecurityKey;
            if (rsaKey != null && rsaKey.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist)
            {
                throw new ArgumentException($"{nameof(JwtService)}::{nameof(ValidateToken)}: You tried to sign a JWT asymmetrically using a public RSA key (the {nameof(rsaKey)} argument). That's not possible! For signing JWTs you need to provide the private key. Public keys are for token validation only.");
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
        /// Validates a JWT <c>string</c> that has been created using the <see cref="GenerateToken"/> method.<para> </para>
        /// If the validation was successful, a <see cref="JwtValidationResult"/> containing both the raw, validated <see cref="JwtSecurityToken"/> and the deserialized <see cref="IPrincipal"/> instance is returned.<para> </para>
        /// If anything went wrong though (invalid, expired, etc...), the returned <see cref="JwtValidationResult"/> object contains information about the failure (e.g. thrown <see cref="Exception"/>, error message <c>string</c>).
        /// </summary>
        /// <param name="jwt">The token to validate (encoded jwt).</param>
        /// <param name="validationParameters">
        ///     The <see cref="TokenValidationParameters"/> to use for validation:
        ///     can be left out <c>null</c> (the parameters defined in the <see cref="JwtService"/> constructor are used in that case).<para> </para>
        ///     If you decide to pass this argument, make absolutely sure that you pass the correct <see cref="TokenValidationParameters.IssuerSigningKey"/> needed for validation, or else you'll run into errors for sure!<para> </para>
        ///     Especially for asymmetrically signed tokens you need to be careful to pass the correct public RSA key.<para> </para>
        ///     For standard symmetric JWTs, that would be the same key you used to generate the token.
        /// </param>
        /// <returns>A <see cref="JwtValidationResult"/> object containing the validation's outcome.</returns>
        public JwtValidationResult ValidateToken(string jwt, TokenValidationParameters validationParameters = null)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                throw new ArgumentException($"{nameof(JwtService)}::{nameof(ValidateToken)}: The {nameof(jwt)} argument is either null or empty! What were you trying to validate?");
            }

            if (validationParameters != null && validationParameters.IssuerSigningKey is null)
            {
                throw new ArgumentException($"{nameof(JwtService)}::{nameof(ValidateToken)}: The {validationParameters} argument's {nameof(validationParameters.IssuerSigningKey)} is null! If you really want to use this overload with the custom validation params, please make sure that they're valid!");
            }

            try
            {
                var claimsPrincipal = jwtSecurityTokenHandler.ValidateToken(jwt, validationParameters ?? this.validationParameters, out var validatedToken);

                return new JwtValidationResult(
                    validatedToken: new Tuple<JwtSecurityToken, IPrincipal>((JwtSecurityToken)validatedToken, claimsPrincipal),
                    exception: null,
                    errorMessage: null
                );
            }
            catch (SecurityTokenExpiredException exception)
            {
                return new JwtValidationResult(
                    validatedToken: null,
                    exception: exception,
                    errorMessage: $"{nameof(JwtService)}::{nameof(ValidateToken)}: The token expired and failed validation: {exception.Message}"
                );
            }
            catch (SecurityTokenNotYetValidException exception)
            {
                return new JwtValidationResult(
                    validatedToken: null,
                    exception: exception,
                    errorMessage: $"{nameof(JwtService)}::{nameof(ValidateToken)}: The token is not yet valid and failed validation: {exception.Message}"
                );
            }
            catch (SecurityTokenInvalidIssuerException exception)
            {
                return new JwtValidationResult(
                    validatedToken: null,
                    exception: exception,
                    errorMessage: $"{nameof(JwtService)}::{nameof(ValidateToken)}: The token's issuer claim is invalid and thus couldn't be validated: {exception.Message}"
                );
            }
            catch (SecurityTokenInvalidAudienceException exception)
            {
                return new JwtValidationResult(
                    validatedToken: null,
                    exception: exception,
                    errorMessage: $"{nameof(JwtService)}::{nameof(ValidateToken)}: The token's audience invalid and thus couldn't be validated: {exception.Message}"
                );
            }
            catch (SecurityTokenValidationException exception)
            {
                return new JwtValidationResult(
                    validatedToken: null,
                    exception: exception,
                    errorMessage: $"{nameof(JwtService)}::{nameof(ValidateToken)}: The token was not well-formed or was invalid for some other reason: {exception.Message}"
                );
            }
            catch (Exception exception)
            {
                return new JwtValidationResult(
                    validatedToken: null,
                    exception: exception,
                    errorMessage: $"{nameof(JwtService)}::{nameof(ValidateToken)}: Token failed validation... Error message: {exception.Message}"
                );
            }
        }
    }
}
