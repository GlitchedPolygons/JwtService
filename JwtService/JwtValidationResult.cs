using System;
using System.Security.Claims;
using System.Security.Principal;
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
