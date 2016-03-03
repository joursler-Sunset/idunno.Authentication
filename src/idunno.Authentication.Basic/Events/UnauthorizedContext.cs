// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNet.Http;

namespace idunno.Authentication.Basic
{
    public class UnauthorizedContext : BaseBasicAuthenticationContext
    {
        public UnauthorizedContext(HttpContext context, BasicAuthenticationOptions options)
            : base(context, options)
        {
        }
    }
}
