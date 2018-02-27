// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace idunno.Authentication.Certificate
{
    public class CertificateForwarderOptions
    {
        /// <summary>
        /// The header name containing the Base64 encoded client certificate.
        /// </summary>
        /// <remarks>
        /// This defaults to X-ARR-ClientCert, which is the header Azure Web Apps uses.
        /// </remarks>
        public string CertificateHeader { get; set; } = "X-ARR-ClientCert";
    }
}
