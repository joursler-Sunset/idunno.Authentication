// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;

namespace idunno.Authentication.Certificate
{
    public class CertificateAuthenticationOptions : AuthenticationSchemeOptions
    {
        public CertificateAuthenticationOptions()
        {
        }

        /// <summary>
        /// Flag indicating whether the client certificate must chain up to a trusted
        /// Certificate Authority.
        /// </summary>
        public bool ValidateCertificateChain { get; set; } = true;

        /// <summary>
        /// Flag indicating whether the client certificate must be suitable for client
        /// authentication, either via the Client Authentication EKU, or having no EKUs
        /// at all.
        /// </summary>
        public bool ValidateCertificateUse { get; set; } = true;

        /// <summary>
        /// Flag indicating whether the client certificate validity period should be checked.
        /// </summary>
        public bool ValidateValidityPeriod { get; set; } = true;

        /// <summary>
        /// The object provided by the application to process events raised by the certificate authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of CertificateAuthenticationEvents
        /// and assign delegates only to the events it wants to process.
        /// </summary>
        public new CertificateAuthenticationEvents Events

        {
            get { return (CertificateAuthenticationEvents)base.Events; }

            set { base.Events = value; }
        }
    }
}
