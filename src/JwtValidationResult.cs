using System;
using System.Security.Claims;
using System.Security.Principal;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

namespace GlitchedPolygons.Services.JwtService
{
    /// <summary>
    /// The resulting object from a JWT-validation induced via <see cref="JwtService.ValidateToken"/>.
    /// </summary>
    public class JwtValidationResult
    {
        /// <summary>
        /// The validated token containing all of its linked <see cref="Claim"/>s and other payload elements.<para> </para>
        /// It's a <see cref="Tuple{JwtSecurityToken, IPrincipal}"/> containing both the raw, validated <see cref="JwtSecurityToken"/> and the deserialized <see cref="IPrincipal"/> instance.
        /// </summary>
        public Tuple<JwtSecurityToken, IPrincipal> ValidatedToken { get; }

        /// <summary>
        /// Gets the associated token's claims (from the JWT payload).
        /// </summary>
        public IEnumerable<Claim> Claims => ValidatedToken?.Item1?.Claims;
        
        /// <summary>
        /// Was the validation successful?
        /// </summary>
        public bool Successful => ValidatedToken != null && Exception == null && string.IsNullOrEmpty(ErrorMessage);

        /// <summary>
        /// The thrown <see cref="Exception"/> in case of a failure.
        /// </summary>
        public Exception Exception { get; }

        /// <summary>
        /// The error message <c>string</c> in case of a failure.
        /// </summary>
        public string ErrorMessage { get; }

        /// <summary>
        /// Get the token's claim by type name
        /// (claims are key-value strings inside the JWT's payload json).
        /// </summary>
        /// <param name="claimKey">The claim key (<see cref="Claim.Type"/>).</param>
        /// <returns>The <see cref="Claim"/> value if it was found inside the JWT claims payload; <c>null</c> otherwise.</returns>
        public Claim this[string claimKey]
        {
            get
            {
                // Return null if the token's validation failed
                // or if it doesn't have any claims at all.
                if (!Successful || Claims is null)
                {
                    return null;
                }

                // Look for the claim inside the validated JWT.
                foreach (var claim in this.Claims)
                {
                    if (string.CompareOrdinal(claimKey, claim.Type) == 0)
                    {
                        return claim;
                    }
                }

                // Return null if the JWT doesn't have any claims matching the passed key name.
                return null;
            }
        }

        /// <summary>
        /// Creates a <see cref="JwtValidationResult"/> instance.
        /// </summary>
        /// <param name="validatedToken">The validated token's <see cref="Tuple"/> containing both the decoded <see cref="JwtSecurityToken"/>
        /// and the <see cref="IPrincipal"/> instance with all of its mapped <see cref="Claim"/>s.</param>
        /// <param name="exception">The thrown <see cref="Exception"/> in case of a failure.</param>
        /// <param name="errorMessage">The error message <c>string</c> in case of a failure.</param>
        public JwtValidationResult(Tuple<JwtSecurityToken, IPrincipal> validatedToken, Exception exception, string errorMessage)
        {
            ValidatedToken = validatedToken;
            Exception = exception;
            ErrorMessage = errorMessage;
        }
    }
}
