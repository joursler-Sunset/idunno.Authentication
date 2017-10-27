# idunno.Authentication.Certificate

*This handler is available for ASP.NET Core 2.0 only. Not due to technical reasons, I'm just lazy.*

This project sort of contains an implementation of [Certificate Authentication](https://tools.ietf.org/html/rfc5246#section-7.4.4) for ASP.NET Core. 
Certificate authentication happens at the TLS level, long before it ever gets to ASP.NET Core, so, more accurately this is an authentication handler
that validates the certificate and then gives you an event where you can resolve that certificate to a ClaimsPrincipal. You must configure your
host for Certificate authentication, be it IIS, Kestrel, Azure Web Applications or whatever else you're using.

## How do I use this?

First acquire an HTTPS certificate, apply it and then configure your host to demand and accept certificates..

In your web application add a reference to the package, then in the `ConfigureServices` method in `startup.cs` call
`app.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme).UseCertificateAuthentication(...);` with your options, 
providing a delegate for `OnValidateCertificate` to validate the client certificate sent with requests and turn that information 
into an `ClaimsPrincipal`, set it on the `context.Principal` property and call `context.Success()`.

If you change your scheme name in the options for the authentication handler you need to change the scheme name in 
`AddAuthentication()` to ensure it's used on every request which ends in an endpoint that requires authorization.

If authentication fails this handler will return a `403 (Forbidden)` response rather a `401 (Unauthorized)` as you
might expect - this is because the authentication should happen during the initial TLS connection - by the time it 
reaches the handler it's too late, and there's no way to actually upgrade the connection from an anonymous connection 
to one with a certificate.

You must also add `app.UseAuthentication();` in the `Configure` method, otherwise nothing will ever get called.

For example;

```c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
            .AddCertificate(options =>
            {
                options.Events = new CertificateAuthenticationEvents
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
            });
    // All the other service configuration.
}

public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    app.UseAuthentication();

    // All the other app configuration.
}
```

In the sample you can see that the delegate takes the subject name from the certificate and constructs a `ClaimsIdentity` from it, 
using the `ClaimsIssuer` from the handler options, then create an `ClaimsPrincipal` from those claims, using the `SchemeName` 
from the handler options, then it finally calls `context.Success();` to show there's been a successful authentication.

## Configuring Certificate Validation

The `CertificateAuthenticationOptions` handler has some built in validations that are the minimium validations you should perform on 
a certificate. Each of these settings are turned on by default.

### ValidateCertificateChain

This check validates that the issuer for the certificate is trusted by the application host OS. If 
you are going to accept self-signed certificates you must disable this check.

### ValidateCertificateUse

This check validates that the certificate presented by the client has the Client Authentication 
extended key use, or no EKUs at all (as the specifications say if no EKU is specified then all EKUs 
are valid). 

### ValidateValidityPeriod

This check validates that the certificate is within its validity period. As the handler runs on every 
request this ensures that a certificate that was valid when it was presented has not expired during
its current session.

### How do I configure my app to require a certificate only on certain paths?

Not possible, remember the certificate exchange is done that the start of the HTTPS conversation, 
it's done by the host, not the app. Kestrel, IIS, Azure Web Apps don't have any configuration for
this sort of thing.

## How do I configure my host to require a certificate?

### Kestrel

In program.cs configure `UseKestrel()` as follows.

```c#
public static IWebHost BuildWebHost(string[] args) =>
    WebHost.CreateDefaultBuilder(args)
           .UseStartup<Startup>()
           .UseKestrel(options =>
           {
               options.Listen(IPAddress.Loopback, 5001, listenOptions =>
               {
                   listenOptions.UseHttps(new HttpsConnectionAdapterOptions
                   {
                       ServerCertificate = /* Your HTTPS Certificae */,
                       ClientCertificateMode = ClientCertificateMode.RequireCertificate
                   });
               });
           })
           .Build();
```

### IIS

In the IIS Manager 

1. Select your Site in the Connections tab.
2. Double click the SSL Settings in the Features View window.
3. Check the `Require SSL` Check Box and select the `Require` radio button under Client Certificates.

![Client Certificate Settings in IIS](README-IISConfig.png "Client Certificate Settings in IIS")

### Azure

See the [Azure documentation](https://docs.microsoft.com/en-us/azure/app-service/app-service-web-configure-tls-mutual-auth).

