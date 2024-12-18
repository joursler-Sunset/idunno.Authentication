﻿// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
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

namespace idunno.Authentication.Basic.Test
{
    [ExcludeFromCodeCoverage]
    public class BasicAuthenticationHandlerTests
    {
        [Fact]
        public async Task VerifySchemeDefaults()
        {
            var services = new ServiceCollection();
            services.AddAuthentication().AddBasic();
            var sp             = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme         = await schemeProvider.GetSchemeAsync(BasicAuthenticationDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal("BasicAuthenticationHandler", scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public void SettingAnAsciiRealmWorks()
        {
            const string realm = "Realm";
            var options = new BasicAuthenticationOptions
                          {
                              Realm = realm
                          };
            Assert.Equal(realm, options.Realm);
        }

        [Fact]
        public void SettingANonAsciiRealmThrows()
        {
            var       options = new BasicAuthenticationOptions();
            Exception ex      = Assert.Throws<ArgumentException>(() => options.Realm = "💩");
            Assert.Equal("Realm must be US ASCII", ex.Message);
        }

        [Fact]
        public async Task NormalRequestPassesThrough()
        {
            var server   = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("https://example.com/");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task NormalWithAuthenticationRequestPassesThrough()
        {
            var server = CreateServer(new BasicAuthenticationOptions());

            var transaction = await SendAsync(server, "https://example.com/", "username", "password");
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
        }


        [Fact]
        public async Task ProtectedPathReturnsUnauthorizedWithWWWAuthenticateHeaderAndScheme()
        {
            var server   = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("https://example.com/unauthorized");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ProtectedPathRequestWithBadSchemeReturnsUnauthorized()
        {
            var server = CreateServer(new BasicAuthenticationOptions());
            var transaction =
                await SendAsync(server, "https://example.com/unauthorized", "username", "password", "bogus");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ForbiddenPathReturnsForbiddenStatus()
        {
            var server   = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("https://example.com/forbidden");
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task
            ChallengePathReturnsUnauthorizedWithWWWAuthenticateHeaderAndSchemeWhenNoAuthenticateHeaderIsPresent()
        {
            var server   = CreateServer(new BasicAuthenticationOptions());
            var response = await server.CreateClient().GetAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Single(response.Headers.WwwAuthenticate);
            Assert.Equal("Basic",      response.Headers.WwwAuthenticate.First().Scheme);
            Assert.Equal("realm=\"\"", response.Headers.WwwAuthenticate.First().Parameter.ToString());
        }


        [Fact]
        public async Task
            ChallengePathReturnsUnauthorizedWithWWWAuthenticateHeaderSchemeAndConfiguredRealmWhenNoAuthenticateHeaderIsPresent()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Realm = "realm"
                                      });
            var response = await server.CreateClient().GetAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Single(response.Headers.WwwAuthenticate);
            Assert.Equal("Basic",           response.Headers.WwwAuthenticate.First().Scheme);
            Assert.Equal("realm=\"realm\"", response.Headers.WwwAuthenticate.First().Parameter.ToString());
        }

        [Fact]
        public async Task
            ChallengePathReturnsUnauthorizedWithWWWAuthenticateHeaderSchemeAndConfiguredRealmAndUnicodeCharsetWhenNoAuthenticateHeaderIsPresentAndAdvertiseEncodingIsTrueAndEncodingPreferenceIsUnicode()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Realm                       = "realm",
                                          AdvertiseEncodingPreference = true,
                                          EncodingPreference          = EncodingPreference.Utf8
                                      });
            var response = await server.CreateClient().GetAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Single(response.Headers.WwwAuthenticate);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);

            var parameters = response.Headers.WwwAuthenticate.First().Parameter.Split(' ');
            Assert.Equal("realm=\"realm\",",  parameters[0]);
            Assert.Equal("charset=\"UTF-8\"", parameters[1]);
        }

        [Fact]
        public async Task
            ChallengePathReturnsUnauthorizedWithWWWAuthenticateHeaderSchemeAndConfiguredRealmAndUnicodeCharsetWhenNoAuthenticateHeaderIsPresentAndAdvertiseEncodingIsTrueAndEncodingPreferenceIsPreferUnicode()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Realm                       = "realm",
                                          AdvertiseEncodingPreference = true,
                                          EncodingPreference          = EncodingPreference.PreferUtf8
                                      });
            var response = await server.CreateClient().GetAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Single(response.Headers.WwwAuthenticate);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);

            var parameters = response.Headers.WwwAuthenticate.First().Parameter.Split(' ');
            Assert.Equal("realm=\"realm\",",  parameters[0]);
            Assert.Equal("charset=\"UTF-8\"", parameters[1]);
        }

        [Fact]
        public async Task
            ChallengePathReturnsUnauthorizedWithWWWAuthenticateHeaderSchemeAndConfiguredRealmAndUnicodeCharsetWhenNoAuthenticateHeaderIsPresentAndAdvertiseEncodingIsTrueAndEncodingPreferenceIsLatin1()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Realm                       = "realm",
                                          AdvertiseEncodingPreference = true,
                                          EncodingPreference          = EncodingPreference.Latin1
                                      });
            var response = await server.CreateClient().GetAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Single(response.Headers.WwwAuthenticate);
            Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);

            var parameters = response.Headers.WwwAuthenticate.First().Parameter.Split(' ');
            Assert.Equal("realm=\"realm\",",       parameters[0]);
            Assert.Equal("charset=\"ISO-8859-1\"", parameters[1]);
        }

        [Fact]
        public async Task ChallengePathReturnsUnauthorizedWhenAnAuthorizeHeaderIsSentAndFailsValidation()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context => { return Task.CompletedTask; }
                                                   }
                                      });

            var transaction = await SendAsync(server, "https://example.com/challenge", "username", "password");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidateOnValidateCredentialsCalledWhenCredentialsProvided()
        {
            bool called = false;
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context =>
                                                                               {
                                                                                   called = true;
                                                                                   return Task.CompletedTask;
                                                                               }
                                                   }
                                      });

            var transaction = await SendAsync(server, "https://example.com/", "username", "password");
            Assert.True(called);
        }

        [Fact]
        public async Task ValidateOnValidateCredentialsIsNotCalledWhenNoCredentialsAreProvided()
        {
            bool called = false;
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context =>
                                                                               {
                                                                                   called = true;
                                                                                   return Task.CompletedTask;
                                                                               }
                                                   }
                                      });

            var transaction = await SendAsync(server, "https://example.com/");
            Assert.False(called);
        }

        [Fact]
        public async Task ValidateUpgradeRequestedReturnedOnHttpRequest()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                      });
            var response = await server.CreateClient().GetAsync("http://example.com/challenge");
            Assert.Equal(StatusCodes.Status421MisdirectedRequest, (int)response.StatusCode);
            Assert.Empty(response.Headers.WwwAuthenticate);
        }

        [Fact]
        public async Task ValidateHandlerWillRespondOnHttpWhenSecurityIsDisabled()
        {
            bool called = false;
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          AllowInsecureProtocol = true,
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context =>
                                                                               {
                                                                                   called = true;
                                                                                   return Task.CompletedTask;
                                                                               }
                                                   }
                                      });

            var transaction = await SendAsync(server, "http://example.com/", "username", "password");
            Assert.True(called);
        }


        [Fact]
        public async Task ValidateOnValidateCredentialsIsNotCalledWhenTheAuthorizationHeaderHasNoCredentials()
        {
            bool called = false;
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context =>
                                                                               {
                                                                                   called = true;
                                                                                   return Task.CompletedTask;
                                                                               }
                                                   }
                                      });

            var transaction = await SendAsyncWithHeaderValue(server, "https://example.com/", "");
            Assert.False(called);
        }

        [Fact]
        public async Task ValidateOnAuthenticationFailedCalledIfExceptionHappensInValidateCredentials()
        {
            const string exceptionMessage = "Something bad happened.";

            bool   called                 = false;
            string actualExceptionMessage = null;

            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context =>
                                                                               {
                                                                                   throw
                                                                                       new Exception(exceptionMessage);
                                                                               },
                                                       OnAuthenticationFailed = context =>
                                                       {
                                                           called                 = true;
                                                           actualExceptionMessage = context.Exception.Message;
                                                           context.Fail(context.Exception.Message);
                                                           return Task.CompletedTask;
                                                       }
                                                   }
                                      });

            var transaction = await SendAsync(server, "http://example.com/", "username", "password");
            Assert.True(called);
            Assert.Equal(exceptionMessage, actualExceptionMessage);
        }

        [Fact]
        public async Task ValidateAuthenticationFailsIfOnValidateCredentialsDoesNothing()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context => { return Task.CompletedTask; }
                                                   }
                                      });

            var transaction = await SendAsync(server, "https://example.com/challenge", "username", "password");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidateAuthenticationFailsIfOnValidateCredentialsFails()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context =>
                                                                               {
                                                                                   context.Fail("Failed");
                                                                                   return Task.CompletedTask;
                                                                               }
                                                   }
                                      });

            var transaction = await SendAsync(server, "https://example.com/challenge", "username", "password");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidateAuthenticationFailsWhenAnInvalidUTF8AuthenticationHeaderIsSent()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                      });

            var transaction = await SendAsyncWithRawHeaderValue(server, "https://example.com/challenge", "%%%%%");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidateSuppressionOfWWWAuthenticationHeader()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          SuppressWWWAuthenticateHeader = true
                                      });
            var response = await server.CreateClient().GetAsync("https://example.com/challenge");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Empty(response.Headers.WwwAuthenticate);
        }

        [Fact]
        public async Task ValidateSuppressionOfWWWAuthenticationHeaderOverridePathNotOverridden()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          SuppressWWWAuthenticateHeader             = true,
                                          SuppressWWWAuthenticateHeaderPathOverride = new[] { "/libraryui" }
                                      });

            var response = await server.CreateClient().GetAsync("https://example.com/libraryui");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Empty(response.Headers.WwwAuthenticate);
        }

        [Fact]
        public async Task ValidateSuppressionOfWWWAuthenticationHeaderOverridePathOverridden()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          SuppressWWWAuthenticateHeader             = true,
                                          SuppressWWWAuthenticateHeaderPathOverride = new[] { "/libraryui" }
                                      });

            var response = await server.CreateClient().GetAsync("https://example.com/libraryui");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Single(response.Headers.WwwAuthenticate);
        }

        [Fact]
        public async Task ValidateAuthenticationHeaderWithOnlySchemeReturnsUnauthorized()
        {
            var server = CreateServer(new BasicAuthenticationOptions());

            var transaction = await SendAsyncWithRawHeaderValue(server, "https://example.com/challenge", " ");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task CredentialsWithoutColonDelimiterReturnsUnauthorized()
        {
            string invalidCredentials = "nocolon";
            string base64EncodedValue =
                Convert.ToBase64String(Encoding.UTF8.GetBytes(invalidCredentials.ToCharArray()));
            var server = CreateServer(new BasicAuthenticationOptions());

            var transaction =
                await SendAsyncWithRawHeaderValue(server, "https://example.com/challenge", base64EncodedValue);
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task InvalidUtf8InAuthorizationHeaderReturnsUnauthorized()
        {
            byte[] invalidUtf8        = { 0xC3, 0x28 };
            string base64EncodedValue = Convert.ToBase64String(invalidUtf8);
            var    server             = CreateServer(new BasicAuthenticationOptions());

            var transaction =
                await SendAsyncWithRawHeaderValue(server, "https://example.com/challenge", base64EncodedValue);
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidatedCredentialsSetCurrentPrincipal()
        {
            const string Expected = "username";

            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context =>
                                                                               {
                                                                                   var claims = new[]
                                                                                       {
                                                                                           new Claim(
                                                                                            ClaimTypes.Name,
                                                                                            context.Username,
                                                                                            ClaimValueTypes.String,
                                                                                            context.Options
                                                                                                .ClaimsIssuer)
                                                                                       };
                                                                                   context.Principal =
                                                                                       new
                                                                                           ClaimsPrincipal(new
                                                                                               ClaimsIdentity(claims,
                                                                                                   context
                                                                                                       .Scheme
                                                                                                       .Name));
                                                                                   context.Success();

                                                                                   return Task.CompletedTask;
                                                                               }
                                                   }
                                      });

            var transaction = await SendAsync(server, "https://example.com/whoami", Expected, "password");
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
            Assert.NotNull(transaction.ResponseElement);
            var actual = transaction.ResponseElement.Elements("claim")
                                    .Where(claim => claim.Attribute("Type").Value == ClaimTypes.Name);
            Assert.Single(actual);
            Assert.Equal(Expected, actual.First().Value);
            Assert.Single(transaction.ResponseElement.Elements("claim"));
        }

        [Fact]
        public async Task ValidateWhenExceptionIsThrownInOnValidateCredentialsItIsRaisedInAuthenticationFailed()
        {
            const string ExceptedExceptionMessage = "oops";

            Exception exceptionRaised = null;
            bool      visited         = false;

            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context =>
                                                                               {
                                                                                   throw new
                                                                                       Exception(ExceptedExceptionMessage);
                                                                               },
                                                       OnAuthenticationFailed = context =>
                                                       {
                                                           visited         = true;
                                                           exceptionRaised = context.Exception;
                                                           context.Fail(exceptionRaised);
                                                           return Task.CompletedTask;
                                                       }
                                                   }
                                      });

            await SendAsync(server, "https://example.com/challenge", "userName", "password");

            Assert.True(visited);
            Assert.IsType<Exception>(exceptionRaised);
            Assert.Equal(ExceptedExceptionMessage, exceptionRaised.Message);
        }

        [Fact]
        public async Task ValidateAuthenticationFailsWhenUsingUtf8DecodingAndPasswordContainsSectionSign()
        {
            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          EncodingPreference = EncodingPreference.Utf8
                                      });

            var transaction = await SendAsync(server, "https://example.com/challenge", "username", "§");
            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ValidateAuthenticationSucceedsWhenUsingLatin1DecodingAndPasswordContainsSectionSign()
        {
            const string Expected = "UserName";

            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          EncodingPreference = EncodingPreference.Latin1,
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context =>
                                                                               {
                                                                                   var claims = new[]
                                                                                       {
                                                                                           new Claim(
                                                                                            ClaimTypes.Name,
                                                                                            context.Username,
                                                                                            ClaimValueTypes.String,
                                                                                            context.Options
                                                                                                .ClaimsIssuer)
                                                                                       };
                                                                                   context.Principal =
                                                                                       new
                                                                                           ClaimsPrincipal(new
                                                                                               ClaimsIdentity(claims,
                                                                                                   context
                                                                                                       .Scheme
                                                                                                       .Name));
                                                                                   context.Success();

                                                                                   return Task.CompletedTask;
                                                                               }
                                                   }
                                      });

            string credentials        = $"{Expected}:pa§§word";
            byte[] credentialsAsBytes = Encoding.GetEncoding("ISO-8859-1").GetBytes(credentials.ToCharArray());
            var    encodedCredentials = Convert.ToBase64String(credentialsAsBytes);

            var transaction =
                await SendAsyncWithRawHeaderValue(server, "https://example.com/whoami", encodedCredentials);
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
            Assert.NotNull(transaction.ResponseElement);
            var actual = transaction.ResponseElement.Elements("claim")
                                    .Where(claim => claim.Attribute("Type").Value == ClaimTypes.Name);
            Assert.Single(actual);
            Assert.Equal(Expected, actual.First().Value);
            Assert.Single(transaction.ResponseElement.Elements("claim"));
        }

        [Fact]
        public async Task ValidateAuthenticationSucceedsWhenUsingLatin1DecodingAndUserNameContainsSectionSign()
        {
            const string Expected = "User§Name";

            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          EncodingPreference = EncodingPreference.Latin1,
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context =>
                                                                               {
                                                                                   var claims = new[]
                                                                                       {
                                                                                           new Claim(
                                                                                            ClaimTypes.Name,
                                                                                            context.Username,
                                                                                            ClaimValueTypes.String,
                                                                                            context.Options
                                                                                                .ClaimsIssuer)
                                                                                       };
                                                                                   context.Principal =
                                                                                       new
                                                                                           ClaimsPrincipal(new
                                                                                               ClaimsIdentity(claims,
                                                                                                   context
                                                                                                       .Scheme
                                                                                                       .Name));
                                                                                   context.Success();

                                                                                   return Task.CompletedTask;
                                                                               }
                                                   }
                                      });

            string credentials        = $"{Expected}:pa§§word";
            byte[] credentialsAsBytes = Encoding.GetEncoding("ISO-8859-1").GetBytes(credentials.ToCharArray());
            var    encodedCredentials = Convert.ToBase64String(credentialsAsBytes);

            var transaction =
                await SendAsyncWithRawHeaderValue(server, "https://example.com/whoami", encodedCredentials);
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
            Assert.NotNull(transaction.ResponseElement);
            var actual = transaction.ResponseElement.Elements("claim")
                                    .Where(claim => claim.Attribute("Type").Value == ClaimTypes.Name);
            Assert.Single(actual);
            Assert.Equal(Expected, actual.First().Value);
            Assert.Single(transaction.ResponseElement.Elements("claim"));
        }

        [Fact]
        public async Task ValidateAuthenticationSucceedsWhenUsingPreferUtf8DecodingAndUserNameContainsSectionSign()
        {
            const string Expected = "User§Name";

            var server = CreateServer(new BasicAuthenticationOptions
                                      {
                                          EncodingPreference = EncodingPreference.PreferUtf8,
                                          Events = new BasicAuthenticationEvents
                                                   {
                                                       OnValidateCredentials = context =>
                                                                               {
                                                                                   var claims = new[]
                                                                                       {
                                                                                           new Claim(
                                                                                            ClaimTypes.Name,
                                                                                            context.Username,
                                                                                            ClaimValueTypes.String,
                                                                                            context.Options
                                                                                                .ClaimsIssuer)
                                                                                       };
                                                                                   context.Principal =
                                                                                       new
                                                                                           ClaimsPrincipal(new
                                                                                               ClaimsIdentity(claims,
                                                                                                   context
                                                                                                       .Scheme
                                                                                                       .Name));
                                                                                   context.Success();

                                                                                   return Task.CompletedTask;
                                                                               }
                                                   }
                                      });

            string credentials        = $"{Expected}:pa§§word";
            byte[] credentialsAsBytes = Encoding.GetEncoding("ISO-8859-1").GetBytes(credentials.ToCharArray());
            var    encodedCredentials = Convert.ToBase64String(credentialsAsBytes);

            var transaction =
                await SendAsyncWithRawHeaderValue(server, "https://example.com/whoami", encodedCredentials);
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
            Assert.NotNull(transaction.ResponseElement);
            var actual = transaction.ResponseElement.Elements("claim")
                                    .Where(claim => claim.Attribute("Type").Value == ClaimTypes.Name);
            Assert.Single(actual);
            Assert.Equal(Expected, actual.First().Value);
            Assert.Single(transaction.ResponseElement.Elements("claim"));
        }

        private static TestServer CreateServer(
            BasicAuthenticationOptions          configureOptions,
            Func<HttpContext, Func<Task>, Task> handler     = null,
            Uri                                 baseAddress = null)
        {
            var builder = new WebHostBuilder()
                          .Configure(app =>
                                     {
                                         if (handler != null)
                                         {
                                             app.Use(handler);
                                         }

                                         app.UseAuthentication();

                                         app.Use(async (context, next) =>
                                                 {
                                                     var request  = context.Request;
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
                                                         await context.ForbidAsync(BasicAuthenticationDefaults
                                                             .AuthenticationScheme);
                                                     }
                                                     else if (request.Path == new PathString("/challenge"))
                                                     {
                                                         await context.ChallengeAsync(BasicAuthenticationDefaults
                                                             .AuthenticationScheme);
                                                     }
                                                     else if (request.Path == new PathString("/libraryui"))
                                                     {
                                                         await context.ChallengeAsync(BasicAuthenticationDefaults
                                                             .AuthenticationScheme);
                                                     }
                                                     else if (request.Path == new PathString("/whoami"))
                                                     {
                                                         var authenticationResult = await context.AuthenticateAsync();
                                                         if (authenticationResult.Succeeded)
                                                         {
                                                             response.StatusCode  = (int)HttpStatusCode.OK;
                                                             response.ContentType = "text/xml";

                                                             await response.WriteAsync("<claims>");
                                                             foreach (Claim claim in context.User.Claims)
                                                             {
                                                                 await response
                                                                     .WriteAsync($"<claim Type=\"{claim.Type}\" Issuer=\"{claim.Issuer}\">{claim.Value}</claim>");
                                                             }

                                                             await response.WriteAsync("</claims>");
                                                         }
                                                         else
                                                         {
                                                             await context.ChallengeAsync();
                                                         }
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
                                                     services.AddAuthentication(BasicAuthenticationDefaults
                                                                                    .AuthenticationScheme)
                                                             .AddBasic(options =>
                                                                       {
                                                                           options.Events = configureOptions.Events;
                                                                           options.Realm  = configureOptions.Realm;
                                                                           options.SuppressWWWAuthenticateHeader =
                                                                               configureOptions
                                                                                   .SuppressWWWAuthenticateHeader;
                                                                           options
                                                                                   .SuppressWWWAuthenticateHeaderPathOverride =
                                                                               configureOptions
                                                                                   .SuppressWWWAuthenticateHeaderPathOverride;
                                                                           options.AdvertiseEncodingPreference =
                                                                               configureOptions
                                                                                   .AdvertiseEncodingPreference;
                                                                           options.EncodingPreference =
                                                                               configureOptions.EncodingPreference;
                                                                       });
                                                 }
                                                 else
                                                 {
                                                     services.AddAuthentication(BasicAuthenticationDefaults
                                                                                    .AuthenticationScheme)
                                                             .AddBasic();
                                                 }
                                             });

            var server = new TestServer(builder)
                         {
                             BaseAddress = baseAddress
                         };

            return server;
        }

        private static async Task<Transaction> SendAsync(TestServer server,          string uri, string userName = null,
                                                         string     password = null, string scheme = "Basic")
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (!string.IsNullOrEmpty(userName))
            {
                string credentials        = $"{userName}:{password}";
                byte[] credentialsAsBytes = Encoding.UTF8.GetBytes(credentials.ToCharArray());
                var    encodedCredentials = Convert.ToBase64String(credentialsAsBytes);
                request.Headers.Add(HeaderNames.Authorization, $"{scheme} {encodedCredentials}");
            }

            var transaction = new Transaction
                              {
                                  Request  = request,
                                  Response = await server.CreateClient().SendAsync(request),
                              };
            transaction.ResponseText = await transaction.Response.Content.ReadAsStringAsync();

            if (transaction.Response.Content                               != null &&
                transaction.Response.Content.Headers.ContentType           != null &&
                transaction.Response.Content.Headers.ContentType.MediaType == "text/xml")
            {
                transaction.ResponseElement = XElement.Parse(transaction.ResponseText);
            }

            return transaction;
        }

        private static async Task<Transaction> SendAsyncWithHeaderValue(TestServer server, string uri,
                                                                        string     authorizationHeaderValue,
                                                                        string     scheme = "Basic")
        {
            var    request            = new HttpRequestMessage(HttpMethod.Get, uri);
            byte[] credentialsAsBytes = Encoding.UTF8.GetBytes(authorizationHeaderValue.ToCharArray());
            var    encodedCredentials = Convert.ToBase64String(credentialsAsBytes);
            request.Headers.Add(HeaderNames.Authorization, scheme + " " + encodedCredentials);

            var transaction = new Transaction
                              {
                                  Request  = request,
                                  Response = await server.CreateClient().SendAsync(request),
                              };
            transaction.ResponseText = await transaction.Response.Content.ReadAsStringAsync();

            if (transaction.Response.Content                               != null &&
                transaction.Response.Content.Headers.ContentType           != null &&
                transaction.Response.Content.Headers.ContentType.MediaType == "text/xml")
            {
                transaction.ResponseElement = XElement.Parse(transaction.ResponseText);
            }

            return transaction;
        }

        private static async Task<Transaction> SendAsyncWithRawHeaderValue(
            TestServer server, string uri, string authorizationHeaderValue, string scheme = "Basic")
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            var addResult =
                request.Headers.TryAddWithoutValidation(HeaderNames.Authorization,
                                                        scheme + " " + authorizationHeaderValue);

            if (!addResult)
            {
                throw new ArgumentException("Could not add authorization header.", nameof(authorizationHeaderValue));
            }

            var transaction = new Transaction
                              {
                                  Request  = request,
                                  Response = await server.CreateClient().SendAsync(request),
                              };
            transaction.ResponseText = await transaction.Response.Content.ReadAsStringAsync();

            if (transaction.Response.Content                               != null &&
                transaction.Response.Content.Headers.ContentType           != null &&
                transaction.Response.Content.Headers.ContentType.MediaType == "text/xml")
            {
                transaction.ResponseElement = XElement.Parse(transaction.ResponseText);
            }

            return transaction;
        }


        private class Transaction
        {
            public HttpRequestMessage  Request         { get; set; }
            public HttpResponseMessage Response        { get; set; }
            public string              ResponseText    { get; set; }
            public XElement            ResponseElement { get; set; }
        }
    }
}