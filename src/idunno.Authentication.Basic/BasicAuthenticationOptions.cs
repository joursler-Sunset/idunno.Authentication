// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNet.Authentication;

namespace idunno.Authentication.Basic
{
    public class BasicAuthenticationOptions : AuthenticationOptions
    {
        public BasicAuthenticationOptions() : base()
        {
            AuthenticationScheme = BasicAuthenticationDefaults.AuthenticationScheme;
            AutomaticAuthenticate = true;
            AutomaticChallenge = true;
        }

        public string Realm { get; set; }

        /// <summary>
        /// The object provided by the application to process events raised by the basic authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of BasicAuthenticationEvents
        /// and assign delegates only to the events it wants to process.
        /// </summary>
        public IBasicAuthenticationEvents Events { get; set; } = new BasicAuthenticationEvents();
    }
}
