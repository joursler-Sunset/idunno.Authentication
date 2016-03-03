// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using idunno.Authentication.Basic;
using Microsoft.AspNet.Builder;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// Extension methods to add Basic authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class BasicAuthenticationAppBuilderExtensions
    {
        public static IApplicationBuilder UseBasicAuthentication(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<BasicAuthenticationMiddleware>();
        }

        public static IApplicationBuilder UseBasicAuthentication(this IApplicationBuilder app, Action<BasicAuthenticationOptions> configureOptions)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            var options = new BasicAuthenticationOptions();
            if (configureOptions != null)
            {
                configureOptions(options);
            }

            return app.UseMiddleware<BasicAuthenticationMiddleware>(options);
        }
    }
}


