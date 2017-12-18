// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

using Microsoft.Net.Http.Headers;

using Xunit;

using idunno.Authentication.Certificate;
using System.Security.Cryptography.X509Certificates;

namespace idunno.Authentication.Test
{
    public class ClientCertificateAuthenticationTests
    {
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

                        if (request.Path == new PathString("/"))
                        {
                            response.StatusCode = (int)HttpStatusCode.OK;
                        }
                        else if (request.Path == new PathString("/unauthorized"))
                        {
                            response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        }
                        else if (request.Path == new PathString("/forbidden"))
                        {
                            await context.ForbidAsync(CertificateAuthenticationDefaults.AuthenticationScheme);
                        }
                        else if (request.Path == new PathString("/challenge"))
                        {
                            await context.ChallengeAsync(CertificateAuthenticationDefaults.AuthenticationScheme);
                        }
                        else
                        {
                            await next();
                        }
                    });
                })
            .ConfigureServices(services =>
            {
                if (configureOptions != null)
                {
                    services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme).AddCertificate(options =>
                    {
                        options.AllowedCertificateTypes = CertificateTypes.SelfSigned | CertificateTypes.TrustedRootChained;
                        options.ValidateCertificateUse = configureOptions.ValidateCertificateUse;
                        options.ValidateValidityPeriod = configureOptions.ValidateValidityPeriod;
                        options.Events = configureOptions.Events;
                    });
                }
                else
                {
                    services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme).AddCertificate();
                }
            });

            var server = new TestServer(builder);
            server.BaseAddress = baseAddress;

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
