// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace idunno.Authentication.Certificate
{
    internal class CertificateAuthenticationHandler : AuthenticationHandler<CertificateAuthenticationOptions>
    {
        public CertificateAuthenticationHandler(
            IOptionsMonitor<CertificateAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new CertificateAuthenticationEvents Events
        {
            get { return (CertificateAuthenticationEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        /// Creates a new instance of the events instance.
        /// </summary>
        /// <returns>A new instance of the events instance.</returns>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new CertificateAuthenticationEvents());

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // You only get client certificates over HTTPS
            if (!Context.Request.IsHttps)
            {
                return AuthenticateResult.NoResult();
            }

            var clientCertificate = await Context.Connection.GetClientCertificateAsync();

            // This should never be the case, as cert auth happens long before ASP.NET kicks in.
            if (clientCertificate == null)
            {
                return AuthenticateResult.NoResult();
            }

            try
            {
                if (Options.ValidateCertificateChain && !IsCertificateChainValid(clientCertificate))
                {
                    return AuthenticateResult.Fail("Client certificate chain validation failure.");
                }

                if (Options.ValidateValidityPeriod && !IsCertificateWithinValidityRange(clientCertificate))
                {
                    return AuthenticateResult.Fail("Client certificate has expired or is not yet valid.");
                }

                if (Options.ValidateCertificateUse && !IsCertificateValidForClientAuthentication(clientCertificate))
                {
                    return AuthenticateResult.Fail("Certificate presented is not valid for client use.");
                }

                var validateCertificateContext = new ValidateCertificateContext(Context, Scheme, Options)
                {
                    ClientCertificate = clientCertificate
                };

                await Events.ValidateCertificate(validateCertificateContext);

                if (validateCertificateContext.Result != null)
                {
                    var ticket = new AuthenticationTicket(validateCertificateContext.Principal, Scheme.Name);
                    return AuthenticateResult.Success(ticket);
                }

                return AuthenticateResult.NoResult();
            }
            catch (Exception ex)
            {
                var authenticationFailedContext = new CertificateAuthenticationFailedContext(Context, Scheme, Options)
                {
                    Exception = ex
                };

                await Events.AuthenticationFailed(authenticationFailedContext);

                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }

                throw;
            }
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            // Certificate auth takes place at the connection level. We can't prompt once we're in
            // user code, so the best thing to do is Forbid, not Challenge.
            Response.StatusCode = 403;
            return Task.CompletedTask;
        }

        private bool IsCertificateChainValid(X509Certificate2 clientCertificate)
        {
            return clientCertificate.Verify();
        }

        private bool IsCertificateValidForClientAuthentication(X509Certificate2 clientCertificate)
        {
            if (clientCertificate.Version >= 3)
            {
                List<X509EnhancedKeyUsageExtension> ekuExtensions = clientCertificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToList();
                if (!ekuExtensions.Any())
                {
                    return true;
                }
                else
                {
                    foreach (var extension in ekuExtensions)
                    {
                        foreach (var oid in extension.EnhancedKeyUsages)
                        {
                            if (oid.Value.Equals("1.3.6.1.5.5.7.3.2", StringComparison.Ordinal))
                            {
                                return true;
                            }
                        }
                    }
                }
            }

            return false;
        }

        private bool IsCertificateWithinValidityRange(X509Certificate2 clientCertificate)
        {
            var now = DateTime.Now;
            if (clientCertificate.NotBefore <= now && clientCertificate.NotAfter >= now)
            {
                return true;
            }
            return false;
        }
    }
}
