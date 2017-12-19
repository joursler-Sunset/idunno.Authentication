// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml.Linq;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

using Xunit;

using idunno.Authentication.Certificate;

namespace idunno.Authentication.Test
{
    public class ClientCertificateAuthenticationTests
    {
        private const string CollateralPath = @"..\..\..\..\collateral\";

        private CertificateAuthenticationEvents sucessfulValidationEvents = new CertificateAuthenticationEvents()
        {
            OnValidateCertificate = context =>
            {
                var claims = new[]
                {
                                new Claim(ClaimTypes.NameIdentifier, context.ClientCertificate.Subject, ClaimValueTypes.String, context.Options.ClaimsIssuer),
                                new Claim(ClaimTypes.Name, context.ClientCertificate.Subject, ClaimValueTypes.String, context.Options.ClaimsIssuer)
                            };

                context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                context.Success();
                return Task.CompletedTask;
            }
        };

        [Fact]
        public async Task VerifySchemeDefaults()
        {
            var services = new ServiceCollection();
            services.AddAuthentication().AddCertificate();
            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme = await schemeProvider.GetSchemeAsync(CertificateAuthenticationDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal("CertificateAuthenticationHandler", scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public void ValidateIsSelfSignedExtensionMethod()
        {
            var clientCertificate = new X509Certificate2(
                CollateralPath + "validSelfSignedClientEkuCertificate.pfx",
                "P@ssw0rd!");

            Assert.True(clientCertificate.IsSelfSigned());
        }

        [Fact]
        public async Task VerifyValidSelfSignedWithClientEkuAuthenticates()
        {
            var clientCertificate = new X509Certificate2(
                CollateralPath + "validSelfSignedClientEkuCertificate.pfx",
                "P@ssw0rd!");

            var server = CreateServer(
                new CertificateAuthenticationOptions
                {
                    AllowedCertificateTypes = CertificateTypes.SelfSigned,
                    Events = sucessfulValidationEvents
                },
                clientCertificate);

            var response = await server.CreateClient().GetAsync("https://example.com/");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task VerifyValidSelfSignedWithNoEkuAuthenticates()
        {
            var clientCertificate = new X509Certificate2(
                CollateralPath + "validSelfSignedNoEkuCertificate.pfx",
                "P@ssw0rd!");

            var server = CreateServer(
                new CertificateAuthenticationOptions
                {
                    AllowedCertificateTypes = CertificateTypes.SelfSigned,
                    Events = sucessfulValidationEvents
                },
                clientCertificate);

            var response = await server.CreateClient().GetAsync("https://example.com/");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task VerifyValidSelfSignedWithClientEkuFailsWhenSelfSignedCertsNotAllowed()
        {
            var currentPath = System.IO.Directory.GetCurrentDirectory();
            var clientCertificate = new X509Certificate2(
                CollateralPath + "validSelfSignedClientEkuCertificate.pfx",
                "P@ssw0rd!");

            var server = CreateServer(
                new CertificateAuthenticationOptions
                {
                    AllowedCertificateTypes = CertificateTypes.Chained
                },
                clientCertificate);

            var response = await server.CreateClient().GetAsync("https://example.com/");
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task VerifyValidSelfSignedWithNoEkuFailsWhenSelfSignedCertsNotAllowed()
        {
            var clientCertificate = new X509Certificate2(
                CollateralPath + "validSelfSignedNoEkuCertificate.pfx",
                "P@ssw0rd!");

            var server = CreateServer(
                new CertificateAuthenticationOptions
                {
                    AllowedCertificateTypes = CertificateTypes.Chained,
                    Events = sucessfulValidationEvents
                },
                clientCertificate);

            var response = await server.CreateClient().GetAsync("https://example.com/");
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task VerifyValidSelfSignedWithServerFailsEvenIfSelfSignedCertsAreAllowed()
        {
            var clientCertificate = new X509Certificate2(
                CollateralPath + "validSelfSignedServerEkuCertificate.pfx",
                "P@ssw0rd!");

            var server = CreateServer(
                new CertificateAuthenticationOptions
                {
                    AllowedCertificateTypes = CertificateTypes.SelfSigned,
                    Events = sucessfulValidationEvents
                },
                clientCertificate);

            var response = await server.CreateClient().GetAsync("https://example.com/");
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task VerifyValidSelfSignedWithServerPassesWhenSelfSignedCertsAreAllowedAndPurposeValidationIsOff()
        {
            var clientCertificate = new X509Certificate2(
                CollateralPath + "validSelfSignedServerEkuCertificate.pfx",
                "P@ssw0rd!");

            var server = CreateServer(
                new CertificateAuthenticationOptions
                {
                    AllowedCertificateTypes = CertificateTypes.SelfSigned,
                    ValidateCertificateUse = false,
                    Events = sucessfulValidationEvents
                },
                clientCertificate);

            var response = await server.CreateClient().GetAsync("https://example.com/");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task VerifyValidSelfSignedWithServerFailsPurposeValidationIsOffButSelfSignedCertsAreNotAllowed()
        {
            var clientCertificate = new X509Certificate2(
                CollateralPath + "validSelfSignedServerEkuCertificate.pfx",
                "P@ssw0rd!");

            var server = CreateServer(
                new CertificateAuthenticationOptions
                {
                    AllowedCertificateTypes = CertificateTypes.Chained,
                    ValidateCertificateUse = false,
                    Events = sucessfulValidationEvents
                },
                clientCertificate);

            var response = await server.CreateClient().GetAsync("https://example.com/");
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        private static TestServer CreateServer(
            CertificateAuthenticationOptions configureOptions,
            X509Certificate2 clientCertificate,
            Func<HttpContext, bool> handler = null,
            Uri baseAddress = null)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                {
                    app.Use((context, next) =>
                    {
                        context.Connection.ClientCertificate = clientCertificate;
                        return next();
                    });

                    app.UseAuthentication();

                    app.Use(async (context, next) =>
                    {
                        var request = context.Request;
                        var response = context.Response;

                        var authenticationResult = await context.AuthenticateAsync();

                        if (authenticationResult.Succeeded)
                        {
                            response.StatusCode = (int)HttpStatusCode.OK;
                        }
                        else
                        {
                            await context.ChallengeAsync();
                        }
                    });
                })
            .ConfigureServices(services =>
            {
                if (configureOptions != null)
                {
                    services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme).AddCertificate(options =>
                    {
                        options.AdditionalTrustedCertificates = configureOptions.AdditionalTrustedCertificates;
                        options.AllowedCertificateTypes = configureOptions.AllowedCertificateTypes;
                        options.Events = configureOptions.Events;
                        options.ValidateCertificateUse = configureOptions.ValidateCertificateUse;
                        options.RevocationFlag = options.RevocationFlag;
                        options.RevocationMode = options.RevocationMode;
                        options.ValidateValidityPeriod = configureOptions.ValidateValidityPeriod;
                    });
                }
                else
                {
                    services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme).AddCertificate();
                }
            });

            var server = new TestServer(builder)
            {
                BaseAddress = baseAddress
            };

            return server;
        }

        private static async Task<Transaction> SendAsync(TestServer server, string uri)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            var transaction = new Transaction
            {
                Request = request,
                Response = await server.CreateClient().SendAsync(request),
            };
            transaction.ResponseText = await transaction.Response.Content.ReadAsStringAsync();

            if (transaction.Response.Content != null &&
                transaction.Response.Content.Headers.ContentType != null &&
                transaction.Response.Content.Headers.ContentType.MediaType == "text/xml")
            {
                transaction.ResponseElement = XElement.Parse(transaction.ResponseText);
            }
            return transaction;
        }

        private class Transaction
        {
            public HttpRequestMessage Request { get; set; }
            public HttpResponseMessage Response { get; set; }
            public string ResponseText { get; set; }
            public XElement ResponseElement { get; set; }
        }
    }
}
