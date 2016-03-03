// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;

namespace idunno.Authentication.Basic
{
    public class BasicAuthenticationEvents : IBasicAuthenticationEvents
    {
        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.FromResult(0);

        public Func<ValidateCredentialsContext, Task> OnValidateCredentials { get; set; } = context => Task.FromResult(0);

        public Func<ForbiddenContext, Task> OnForbidden { get; set; } = context => Task.FromResult(0);

        public Func<UnauthorizedContext, Task> OnUnauthorized { get; set; } = context => Task.FromResult(0);

        public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

        public virtual Task ValidateCredentials(ValidateCredentialsContext context) => OnValidateCredentials(context);

        public virtual Task Forbidden(ForbiddenContext context) => OnForbidden(context);

        public virtual Task Unauthorized(UnauthorizedContext context) => OnUnauthorized(context);
    }
}
