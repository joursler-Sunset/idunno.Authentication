﻿// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Authentication;

namespace idunno.Authentication.Basic
{
    /// <summary>
    /// Contains the options used by the BasicAuthenticationMiddleware
    /// </summary>
    /// <summary>
    /// Contains the options used by the BasicAuthenticationMiddleware
    /// </summary>
    public class BasicAuthenticationOptions : AuthenticationSchemeOptions
    {
        private string _realm;

        /// <summary>
        /// Create an instance of the options initialized with the default values
        /// </summary>
        public BasicAuthenticationOptions()
        {
        }

        /// <summary>
        /// Gets or sets the Realm sent in the WWW-Authenticate header.
        /// </summary>
        /// <remarks>
        /// The realm value (case-sensitive), in combination with the canonical root URL
        /// of the server being accessed, defines the protection space.
        /// These realms allow the protected resources on a server to be partitioned into a
        /// set of protection spaces, each with its own authentication scheme and/or
        /// authorization database.
        /// </remarks>
        public string Realm
        {
            get { return _realm; }

            set
            {
                if (!string.IsNullOrEmpty(value) && !IsAscii(value))
                {
                    throw new ArgumentException("Realm must be US ASCII");
                }

                _realm = value;
            }
        }


        /// <summary>
        /// Gets or sets the a flag indicating if the WWW-Authenticate header will be suppressed on Unauthorized responses.
        /// </summary>
        /// <remarks>
        /// The authentication scheme controls the browser UI and allows the browser to
        /// authenticate in the correct manner, popping up a UI to allow for user name and password.
        /// Some users may want to suppress this behaviour for JavaScript XMLHttpRequest requests.
        /// Setting this flag to true suppresses the WWW-Authenticate header and thus the browser login prompt, just sending a
        /// 401 status code that you must react to yourself in your client code.
        /// </remarks>
        public bool SuppressWWWAuthenticateHeader { get; set; } = false;


        /// <summary>
        /// Reverses the SuppressWWWAuthenticateHeader for specific paths.
        /// </summary>
        /// /// <remarks>
        /// The authentication scheme controls the browser UI and allows the browser to
        /// authenticate in the correct manner, popping up a UI to allow for user name and password.
        /// Some users may want to suppress this behaviour for JavaScript XMLHttpRequest requests while
        /// also having www.example.com/libraryUi use basic auth while returning the WWW-Authenticate header to force a browser login prompt.
        /// The switch happens based on Path StartsWith.
        /// If SuppressWWWAuthenticateHeader is set to false, any path here will set the value to true.
        /// If SuppressWWWAuthenticateHeader is set to true, any path here will set the value to false.
        /// </remarks>
        public string[] SuppressWWWAuthenticateHeaderPathOverride { get; set; } = new string[0];

        /// <summary>
        /// Gets or sets a flag indicating if the handler will prompt for authentication on HTTP requests.
        /// </summary>
        /// <remarks>
        /// If you set this to true you're a horrible person.
        /// </remarks>
        public bool AllowInsecureProtocol { get; set; } = false;

        /// <summary>
        /// Sets or sets a value indicating which Encoding method(s) should be used when
        /// decoding the user name and/or password specified on the incoming Authorization header.
        /// </summary>
        /// <remarks>
        /// The default value for this setting is Unicode.
        /// </remarks>
        public EncodingPreference EncodingPreference { get; set; } = EncodingPreference.Utf8;

        /// <summary>
        /// Sets or sets a value indicating whether the <see cref="EncodingPreference"/>
        /// is appended to the WWW-Authenticate header sent to the client.
        /// If either of the Prefer values are used for encoding preference only the
        /// first encoding will be advertised.
        /// </summary>
        public bool AdvertiseEncodingPreference { get; set; } = false;

        /// <summary>
        /// The object provided by the application to process events raised by the basic authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of BasicAuthenticationEvents
        /// and assign delegates only to the events it wants to process.
        /// </summary>
        public new BasicAuthenticationEvents Events

        {
            get { return (BasicAuthenticationEvents)base.Events; }

            set { base.Events = value; }
        }


        private static bool IsAscii(string input)
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