using AspNet.Security.OpenId.Steam;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using OpenIddict.Abstractions;
using System;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIdDict
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "OpenIdDict", Version = "v1" });
            });

            services.AddAuthentication()
            .AddCookie()
            .AddSteam(options =>
            {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                // To get additional claims from Steam's authentication APIs,
                // register your application and set the application key.
                //
                // options.ApplicationKey = "application_key";
            });

            services.AddOpenIddict()
            .AddServer(options =>
            {
                // Enable the required endpoints
                options.SetTokenEndpointUris("/connect/token");

                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();
                
                options.AllowPasswordFlow();
                options.AllowRefreshTokenFlow();

                // Accept anonymous clients (i.e clients that don't send a client_id).
                options.AcceptAnonymousClients();

                // Set the lifetime of your tokens
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(1));
                options.SetRefreshTokenLifetime(TimeSpan.FromMinutes(4));

                options.UseDataProtection();

                options.EnableDegradedMode();
                options.UseAspNetCore().EnableTokenEndpointPassthrough();

                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        if (!string.Equals(context.ClientId, "console_app", StringComparison.Ordinal))
                        {
                            context.Reject(
                                error: Errors.InvalidClient,
                                description: "The specified 'client_id' doesn't match a registered application.");
                            return default;
                        }
                        if (!string.Equals(context.RedirectUri, "http://localhost:7890/", StringComparison.Ordinal))
                        {
                            context.Reject(
                                error: Errors.InvalidClient,
                                description: "The specified 'redirect_uri' is not valid for this client application.");
                            return default;
                        }
                        return default;
                    }));

                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        //if (!string.Equals(context.ClientId, "console_app", StringComparison.Ordinal))
                        //{
                        //    context.Reject(
                        //        error: Errors.InvalidClient,
                        //        description: "The specified 'client_id' doesn't match a registered application.");
                        //    return default;
                        //}
                        // This demo is used by a single public client application.
                        // As such, no client secret validation is performed.
                        return default;
                    }));

                //options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                //    builder.UseInlineHandler(async context =>
                //    {
                //        var request = context.Transaction.GetHttpRequest() ??
                //            throw new InvalidOperationException("The ASP.NET Core request cannot be retrieved.");
                //        // Retrieve the security principal created by the Steam handler and stored in the authentication cookie.
                //        // If the principal cannot be retrieved, this indicates that the user is not logged in. In this case,
                //        // an authentication challenge is triggered to redirect the user to Steam's authentication endpoint.
                //        var principal = (await request.HttpContext.AuthenticateAsync(SteamAuthenticationDefaults.AuthenticationScheme))?.Principal;
                //        if (principal == null)
                //        {
                //            await request.HttpContext.ChallengeAsync(SteamAuthenticationDefaults.AuthenticationScheme);
                //            context.HandleRequest();
                //            return;
                //        }
                //        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
                //        // Use the "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" claim
                //        // (added by the Steam handler to store the user identifier) as the OIDC "sub" claim.
                //        identity.AddClaim(new Claim(Claims.Subject, principal.GetClaim(ClaimTypes.NameIdentifier)));
                //        // If needed, you can copy more claims from the cookies principal to the bearer principal.
                //        // To get more claims from the Steam handler, you'll need to set the application key.
                //        // Mark all the added claims as being allowed to be persisted in the access token,
                //        // so that the API controllers can retrieve them from the ClaimsPrincipal instance.
                //        foreach (var claim in identity.Claims)
                //        {
                //            claim.SetDestinations(Destinations.AccessToken);
                //        }
                //        // Attach the principal to the authorization context, so that an OpenID Connect response
                //        // with an authorization code can be generated by the OpenIddict server services.
                //        context.Principal = new ClaimsPrincipal(identity);
                //    }));

                //options.AddEventHandler<HandleTokenRequestContext>(b =>
                //b.UseInlineHandler(context =>
                //{
                //    if (!context.Request.IsPasswordGrantType())
                //    {
                //        throw new InvalidOperationException("The specified grant type is not supported.");
                //    }
                //    // Validate the username/password parameters.
                //    // In a real world application, you'd use likely use a key derivation function like PBKDF2 to slow
                //    // the client secret validation process down and a time-constant comparer to prevent timing attacks.
                //    if (!string.Equals(context.Request.Username, "alice@wonderland.com", StringComparison.Ordinal) ||
                //        !string.Equals(context.Request.Password, "P@ssw0rd", StringComparison.Ordinal))
                //    {
                //        context.Reject(
                //            error: Errors.InvalidGrant,
                //            description: "The username/password couple is invalid.");
                //        return default;
                //    }
                //    var principal = new ClaimsPrincipal(new ClaimsIdentity(SteamAuthenticationDefaults.AuthenticationScheme));
                //    principal.SetClaim(Claims.Subject, "Bob");
                //    context.Principal = principal;
                //    return default;
                //}));
            })
            .AddValidation(options =>
            {
                options.UseDataProtection();
                options.UseLocalServer();
                options.UseAspNetCore();
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "OpenIdDict v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}