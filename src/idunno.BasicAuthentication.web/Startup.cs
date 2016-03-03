using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Mvc.Filters;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

using idunno.Authentication.Basic;

namespace idunno.BasicAuthentication.Web
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                options.AddPolicy("AlwaysFail", policy => policy.Requirements.Add(new AlwaysFailRequirement()));

            });
            services.AddMvc(config =>
            {
                var policy = new AuthorizationPolicyBuilder()
                                 .RequireAuthenticatedUser()
                                 .Build();
                config.Filters.Add(new AuthorizeFilter(policy));
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseIISPlatformHandler();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStatusCodePages();

            app.UseBasicAuthentication(options => 
            {
                options.Realm = "idunno";
                options.Events = new BasicAuthenticationEvents
                {
                    OnValidateCredentials = context =>
                    {
                        if (context.Username == context.Password)
                        {

                            var claims = new[]
                            {
                                new Claim(ClaimTypes.NameIdentifier, context.Username)
                            };

                            context.AuthenticationTicket = new AuthenticationTicket(
                                new ClaimsPrincipal(new ClaimsIdentity(claims, context.Options.AuthenticationScheme)),
                                new AuthenticationProperties(), context.Options.AuthenticationScheme);

                            context.HandleResponse();
                        }

                        return Task.FromResult<object>(null);
                    }
                };
            });

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                     name: "default",
                     template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        // Entry point for the application.
        public static void Main(string[] args) => WebApplication.Run<Startup>(args);
    }
}
