// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNet.Authentication;
using System;

namespace idunno.Authentication.Basic
{
    public class BasicAuthenticationOptions : AuthenticationOptions
    {
        string _realm;

        public BasicAuthenticationOptions() : base()
        {
            AuthenticationScheme = BasicAuthenticationDefaults.AuthenticationScheme;
            AutomaticAuthenticate = true;
            AutomaticChallenge = true;
        }

        public string Realm
        {
            get
            {
                return _realm;
            }

            set
            {
                if (!IsAscii(value))
                {
                    throw new ArgumentOutOfRangeException("Realm", "Realm must be US ASCII");
                }

                _realm = value;
            }
        }

        /// <summary>
        /// The object provided by the application to process events raised by the basic authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of BasicAuthenticationEvents
        /// and assign delegates only to the events it wants to process.
        /// </summary>
        public IBasicAuthenticationEvents Events { get; set; } = new BasicAuthenticationEvents();

        private bool IsAscii(string input)
        {
            foreach (char c in input)
            {
                if (c < 32 || c >= 127)
                {
                    return false;
                }
            }

            return true;
        }

    }
}
