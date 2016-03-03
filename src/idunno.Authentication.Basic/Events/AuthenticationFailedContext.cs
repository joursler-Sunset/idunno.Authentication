// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

using Microsoft.AspNet.Http;

namespace idunno.Authentication.Basic
{
    public class AuthenticationFailedContext : BaseBasicAuthenticationContext
    {
        public AuthenticationFailedContext(HttpContext context, BasicAuthenticationOptions options)
            : base(context, options)
        {
        }

        public Exception Exception { get; set; }
    }
}
