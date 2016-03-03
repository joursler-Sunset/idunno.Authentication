// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Threading.Tasks;

namespace idunno.Authentication.Basic
{
    public interface IBasicAuthenticationEvents
    {
        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        Task AuthenticationFailed(AuthenticationFailedContext context);

        /// <summary>
        /// Invoked with the header that has been extracted from the protocol message.
        /// </summary>
        Task ValidateCredentials(ValidateCredentialsContext context);

        /// <summary>
        /// Invoked when an attempt to made to access a protected resource, but the request
        /// is unauthenticated.
        /// </summary>
        Task Unauthorized(UnauthorizedContext context);

        /// <summary>
        /// Invoked when an attempt to made to access a protected resource, but the request
        /// is authenticated but does not match the requirements for access.
        /// </summary>
        Task Forbidden(ForbiddenContext context);
    }
}
