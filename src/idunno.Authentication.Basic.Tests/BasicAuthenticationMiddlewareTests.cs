
using System;
using System.Security.Claims;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.TestHost;
using Microsoft.AspNet.Builder;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Http.Features.Authentication;
using System.Net.Http;
using System.Xml.Linq;
using System.Threading.Tasks;
using System.Text;
using Microsoft.Net.Http.Headers;
using System.Net;
using System.Linq;
using Microsoft.AspNet.Authentication;

namespace idunno.Authentication.Basic.Tests
{
    public class BasicAuthenticationMiddlewareTests
    {
        [Fact]
        public void SettingANonAsciiRealmThrows()
        {
            var options = new BasicAuthenticationOptions();
            Exception ex = Assert.Throws<ArgumentOutOfRangeException>(() => options.Realm = "💩");
            Assert.Equal(ex.Message, "Realm must be US ASCII\r\nParameter name: Realm");
        }

        [Fact]
        public async Task NormalRequestPassesThrough()
        {
            var server = CreateServer(options =>
            {
            });
            var response = await server.CreateClient().GetAsync("http://example.com/");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task NormalWithAuthRequestPassesThrough()
        {
            var server = CreateServer(options =>
            {
            });

            var transaction = await SendAsync(server, "http://example.com/", "username", "password");       
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ProtectedPathReturnsUnauthorizedWithWWWAuthenicateHeaderAndScheme()
        {
            var server = CreateServer(options =>
            {
            });
            var response = await server.CreateClient().GetAsync("http://example.com/unauthorized");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(1, response.Headers.WwwAuthenticate.Count);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);
            Assert.Equal("realm=\"\"", response.Headers.WwwAuthenticate.First().Parameter);
        }

        [Fact]
        public async Task ProtectedPathReturnsUnauthorizedWithWWWAuthenicateHeaderAndSchemeWithSpecifiedRealm()
        {
            var server = CreateServer(options =>
            {
                options.Realm = "realm";
            });
            var response = await server.CreateClient().GetAsync("http://example.com/unauthorized");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(1, response.Headers.WwwAuthenticate.Count);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);
            Assert.Equal("realm=\"realm\"", response.Headers.WwwAuthenticate.First().Parameter);
        }

        [Fact]
        public async Task ForbiddenPathReturnsForbiddenStatus()
        {
            var server = CreateServer(options =>
            {
            });
            var response = await server.CreateClient().GetAsync("http://example.com/forbidden");
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task ChallengePathReturnsUnauthorizedWithWWWAuthenicateHeaderAndSchemeWhenNoAuthenticateHeaderIsPresent()
        {
            var server = CreateServer(options =>
            {
            });
            var response = await server.CreateClient().GetAsync("http://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(1, response.Headers.WwwAuthenticate.Count);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);
            Assert.Equal("realm=\"\"", response.Headers.WwwAuthenticate.First().Parameter);
        }

        [Fact]
        public async Task ChallengePathReturnsUnauthorizedWithWWWAuthenicateHeaderSchemeAndConfiguredRealmWhenNoAuthenticateHeaderIsPresent()
        {
            var server = CreateServer(options =>
            {
                options.Realm = "realm";
            });
            var response = await server.CreateClient().GetAsync("http://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(1, response.Headers.WwwAuthenticate.Count);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);
            Assert.Equal("realm=\"realm\"", response.Headers.WwwAuthenticate.First().Parameter);
        }

        [Fact]
        public async Task ChallengePathReturnsForbiddenWhenAnAuthorizeHeaderIsSentAndPassesValidation()
        {
            var server = CreateServer(options =>
            {
                options.Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        var claims = new[]
                        {
                            new Claim(ClaimTypes.NameIdentifier, context.Username)
                        };

                        context.AuthenticationTicket = new AuthenticationTicket(
                            new ClaimsPrincipal(new ClaimsIdentity(claims, context.Options.AuthenticationScheme)),
                            new AuthenticationProperties(), context.Options.AuthenticationScheme);

                        context.HandleResponse();

                        return Task.FromResult<object>(null);
                    }
                };
            });

            var transaction = await SendAsync(server, "http://example.com/challenge", "username", "password");
            Assert.Equal(HttpStatusCode.Forbidden, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ChallengePathReturnsUnauthorizeWhenAnAuthorizeHeaderIsSentAndFailsValidation()
        {
            var server = CreateServer(options =>
            {
                options.Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {

                        return Task.FromResult<object>(null);
                    }
                };
            });

            var transaction = await SendAsync(server, "http://example.com/challenge", "username", "password");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidateOnValidateCredentialsCalledWhenCredentialsProvided()
        {
            bool called = false;
            var server = CreateServer(options =>
            {
                options.Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        called = true;
                        return Task.FromResult<object>(null);
                    }
                };
            });

            var transaction = await SendAsync(server, "http://example.com/", "username", "password");
            Assert.Equal(true, called);
        }

        [Fact]
        public async Task ValidateOnValidateCredentialsIsNotCalledWhenNoCredentialsAreProvided()
        {
            bool called = false;
            var server = CreateServer(options =>
            {
                options.Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        called = true;
                        return Task.FromResult<object>(null);
                    }
                };
            });

            var transaction = await SendAsync(server, "http://example.com/");
            Assert.Equal(false, called);
        }

        [Fact]
        public async Task ValidateOnForbiddenCalledWhenForbiddenStatusIsReturned()
        {
            bool called = false;
            var server = CreateServer(options =>
            {
                options.Events = new BasicAuthenticationEvents
                {
                    OnForbidden = context =>
                    {
                        called = true;
                        return Task.FromResult<object>(null);
                    }
                };
            });

            var transaction = await SendAsync(server, "http://example.com/forbidden", "username", "password");
            Assert.Equal(true, called);
        }

        [Fact]
        public async Task ValidateOnUnauthorizedCalledWhenUnauthorizedStatusIsReturned()
        {
            bool called = false;
            var server = CreateServer(options =>
            {
                options.Events = new BasicAuthenticationEvents
                {
                    OnUnauthorized = context =>
                    {
                        called = true;
                        return Task.FromResult<object>(null);
                    }
                };
            });

            var transaction = await SendAsync(server, "http://example.com/unauthorized", "username", "password");
            Assert.Equal(true, called);
        }

        private static TestServer CreateServer(
            Action<BasicAuthenticationOptions> configureOptions, 
            Func<HttpContext, bool> handler = null,
            Uri baseAddress = null)
        {
            var server = TestServer.Create(app =>
            {
                if (configureOptions != null)
                {
                    app.UseBasicAuthentication(configureOptions);
                }

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
                        await context.Authentication.ForbidAsync(BasicAuthenticationDefaults.AuthenticationScheme);
                    }
                    else if (request.Path == new PathString("/challenge"))
                    {
                        await context.Authentication.ChallengeAsync(BasicAuthenticationDefaults.AuthenticationScheme, new AuthenticationProperties());
                    }
                    else
                    {
                        await next();
                    }
                });
            },
            services => services.AddAuthentication());
            server.BaseAddress = baseAddress;
            return server;
        }

        private static async Task<Transaction> SendAsync(TestServer server, string uri, string userName = null, string password = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (!string.IsNullOrEmpty(userName))
            {
                string credentials = $"{userName}:{password}";
                byte[] credentialsAsBytes = Encoding.UTF8.GetBytes(credentials.ToCharArray());
                var encodedCredentials = Convert.ToBase64String(credentialsAsBytes);
                request.Headers.Add(HeaderNames.Authorization, $"Basic {encodedCredentials}");
            }
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
