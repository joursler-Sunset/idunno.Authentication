// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Security.Cryptography;
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
        private static Oid ClientCertificateOid = new Oid("1.3.6.1.5.5.7.3.2");

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
                Logger.LogDebug("No client certificate found.");
                return AuthenticateResult.NoResult();
            }

            bool isOfferedCertificateSelfSigned =
                clientCertificate.SubjectName.RawData.SequenceEqual(clientCertificate.IssuerName.RawData);

            // If we have a self signed cert, and they're not allowed, exit early and not bother with
            // any other validations.
            if (isOfferedCertificateSelfSigned &&
                !Options.AllowedCertificateTypes.HasFlag(CertificateTypes.SelfSigned))
            {
                Logger.LogWarning("Self signed certificate rejected, subject was {0}", clientCertificate.Subject);

                return AuthenticateResult.Fail("Options do not allow self signed certificates.");
            }

            // Now build the chain validation options.

            Oid[] applicationPolicy = new Oid[0];
            X509VerificationFlags verificationFlags = X509VerificationFlags.AllFlags;
            X509RevocationFlag revocationFlag = Options.RevocationFlag;
            X509RevocationMode revocationMode = Options.RevocationMode;

            if (isOfferedCertificateSelfSigned)
            {
                // Turn off chain validation, because we have a self signed certificate.
                revocationFlag = X509RevocationFlag.EndCertificateOnly;
                revocationMode = X509RevocationMode.NoCheck;
                verificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority |
                                    X509VerificationFlags.IgnoreEndRevocationUnknown;
            }

            if (!Options.ValidateValidityPeriod)
            {
                verificationFlags = verificationFlags | X509VerificationFlags.IgnoreNotTimeValid;
            }

            X509ChainPolicy chainPolicy;

            if (Options.ValidateCertificateUse)
            {
                chainPolicy = new X509ChainPolicy
                {
                    ApplicationPolicy = { ClientCertificateOid },
                    RevocationFlag = revocationFlag,
                    RevocationMode = revocationMode,
                    VerificationFlags = verificationFlags,
                };
            }
            else
            {
                chainPolicy = new X509ChainPolicy
                {
                    RevocationFlag = revocationFlag,
                    RevocationMode = revocationMode,
                    VerificationFlags = verificationFlags,
                };
            }

            try
            {
                var chain = new X509Chain
                {
                    ChainPolicy = chainPolicy
                };

                var certificateIsValid = chain.Build(clientCertificate);

                if (!certificateIsValid)
                {
                    Logger.LogWarning("Client certificate failed validation, subject was {0}", clientCertificate.Subject);
                    return AuthenticateResult.Fail("Client certificate failed validation.");
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
    }
}
