# idunno.Authentication

This project contains an implementation of [Basic Authentication](https://tools.ietf.org/html/rfc1945#section-11) for ASP.NET Core. 

It is meant as a demonstration of how to write authentication middleware and **not** as something you would seriously consider using.

## How do I use this?

First acquire an HTTPS certificate (see Notes below). Apply it to your website. Remember to renew it in two years.

Remember this is meant as a demonstration on how to write middleware. Yes, this could be easier, 
I could put a package on nuget, but **it's not meant to be for use in production**.

In your web application add a reference to the package, then in the `Configure` method in `startup.cs` call
`app.UseBasicAuthentication()`, providing a delegate for `OnValidateCredentials` to validate any 
user name and password sent with requests and turn that information into an AuthenticationTicket, set it
on the `context.AuthenticationTicket` property and call `context.HandleResponse()`.

You can also specify the Realm used to isolate areas of a web site from one another.

For example;

```c#
app.UseBasicAuthentication(new BasicAuthenticationOptions 
{
    Realm = "idunno",
    Events = new BasicAuthenticationEvents
    {
        OnValidateCredentials = context =>
        {
            if (context.Username == context.Password)
            {
                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, context.Username)
                };

                context.Ticket = new AuthenticationTicket(
                    new ClaimsPrincipal(
					    new ClaimsIdentity(claims, context.Options.AuthenticationScheme)),
                    new AuthenticationProperties(), 
					context.Options.AuthenticationScheme);
             }

             return Task.FromResult<object>(null);
         }
     }
});
```

In the sample you can see that the delegate checks if the user name and password are identical. If they
are then it will consider that a valid login, create claims from the ticket, then create an
`Authentication` ticket containing a principal which contains the claims, then tell ASP.NET Core it 
has handled the authentication request.

Of course you'd never implement such a simple validator would you? No? Good. Have a cookie.

## How do I use this in production?

Seriously? I'd never recommend you use basic authentication in production, but if you must here are some ideas on how to harden it. 

1. In your `OnValidateCredentials` implementation keep a count of failed login attempts, and the IP addresses they come from.
2. Lock out accounts after X failed login attempts, where X is a count you feel is reasonable for your situation.
3. Implement the lock out so it unlocks after Y minutes. In case of repeated attacks increase Y.
4. Be careful when locking out your administration accounts. Have at least one admin account that is not exposed via basic auth, so an attacker cannot lock you out of your site just by sending an incorrect password.
5. Throttle attempts from an IP address, especially one which sends lots of incorrect passwords. Considering dropping/banning attempts from an IP address that appears to be under the control of an attacker. Only you can decide what this means, what consitutes legimate traffic varies from application to application.
6. Always use HTTPS. Redirect all HTTP traffic to HTTPS using `[RequireHttps]`. You can apply this to all of your site via a filter;

    ```c#
    services.Configure<MvcOptions>(options =>
    {
        options.Filters.Add(new RequireHttpsAttribute());
    }
    ```
7. Consider implementing HSTS. 
8. Reconsider your life choices, and look at using OAuth2 or OpenIDConnect instead.

### Notes

Basic Authentication sends credentials unencrypted. You should only use it over [HTTPS](https://en.wikipedia.org/wiki/HTTPS). 

It may also have performance impacts, credentials are sent and validated with every request. As you should not be storing passwords in clear text your validation procedure will have to hash and compare values
with every request, or cache results of previous hashes (which could lead to data leakage). 

Remember that hash comparisons should be time consistent to avoid [timing attacks](https://en.wikipedia.org/wiki/Timing_attack).
