using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authentication.AzureADB2C.UI;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
//using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AzureB2C
{
    public class Startup
    {
        private readonly ILogger<Startup> logger;
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration, ILogger<Startup> logger)
        {
            Configuration = configuration;
            this.logger = logger;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {

                options.CheckConsentNeeded = context => true;// This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            //people are always not aware of case sensitivity
            var b2cConfigurationSection = Configuration.GetSection("AzureADB2C") ?? Configuration.GetSection("AzureAdB2C");

            services.AddAuthentication(AzureADB2CDefaults.AuthenticationScheme)
                .AddAzureADB2C(options => { b2cConfigurationSection.Bind(options); })
                //.AddAzureADB2CBearer(x => { })
                ;

            #region MyRegion
            //after: AddAzureADB2C
            var sp = services.BuildServiceProvider();
            var azureADB2COptions = sp.GetService<IOptionsMonitor<AzureADB2COptions>>().Get(AzureADB2CDefaults.AuthenticationScheme);
            //var openIdConnectOptions = sp.GetService<IOptionsMonitor<OpenIdConnectOptions>>().Get(AzureADB2CDefaults.AuthenticationScheme);
            AddRole_B2c(services, azureADB2COptions);


            fixAccessDenied(services);
            #endregion


            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");

                app.UseHsts();// The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseAuthentication();

            app.UseMvc();
        }

        /// <summary>
        /// fix AccessDenied wrong path(a small bug, PR approved already).
        /// </summary>
        /// <param name="services"></param>
        private static void fixAccessDenied(IServiceCollection services)
        {
            services.Configure<CookieAuthenticationOptions>(AzureADB2CDefaults.CookieScheme, options =>
            {
                options.AccessDeniedPath = "/AzureADB2C/Account/AccessDenied";
            });
        }

        private void AddRole_B2c(IServiceCollection services, AzureADB2COptions azureADB2COptions)
        {

            services.Configure<OpenIdConnectOptions>(AzureADB2CDefaults.OpenIdScheme, (OpenIdConnectOptions options) =>
            {
                options.Events.OnTokenValidated = async context =>
                {
                    var code = context.ProtocolMessage.Code;
                    var accessToken = await getAdTokenAsync();

                    var userId = context.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                    var claimsIdentity = (ClaimsIdentity)context.Principal.Identity;

                    //TokenCache userTokenCache = new MSALSessionCache(signedInUserID, context.HttpContext).GetMsalCacheInstance();
                    //ConfidentialClientApplication cca = new ConfidentialClientApplication(
                    //      clientId: azureADB2COptions.ClientId,
                    //      authority: options.Authority,
                    //      redirectUri: options.CallbackPath,
                    //      clientCredential: new Microsoft.Identity.Client.ClientCredential(azureADB2COptions.ClientSecret),
                    //      userTokenCache: null,
                    //      appTokenCache: null);
                    //try
                    //{
                    //    Microsoft.Identity.Client.AuthenticationResult result = await cca.AcquireTokenByAuthorizationCodeAsync(code, options.Scope);
                    //    context.HandleCodeRedemption(result.AccessToken, result.IdToken);

                    //}
                    //catch (Exception ex)
                    //{

                    //    throw ex;
                    //}

                    using (var client = new HttpClient())
                    {
                        string requestUrl = $"https://graph.microsoft.com/v1.0/users/{userId}/memberOf?$select=displayName";
                        //requestUrl = $"https://graph.windows.net/myB2cTenant.onmicrosoft.com/users/{userId}/memberOf?api-version=1.6";
                        requestUrl = $"https://graph.windows.net/{azureADB2COptions.Domain}/users/{userId}/memberOf?api-version=1.6";
                        //requestUrl = "https://graph.microsoft.com/v1.0/me/memberOf";

                        HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                        HttpResponseMessage response = await client.SendAsync(request);
                        var content = await response.Content.ReadAsStringAsync();

                        var jsonSettings = new JsonSerializerSettings() { Formatting = Formatting.Indented, };
                        if (response.IsSuccessStatusCode)
                        {
                            var formatted = JObject.Parse(content);
                            var jo_groups = formatted["value"] as JArray;

                            foreach (var item in jo_groups)
                            {
                                var groupName = (string)item["displayName"];
                                claimsIdentity.AddClaim(new Claim(type: ClaimTypes.Role, value: groupName));
                            }
                        }
                        else
                        {
                            logger.LogWarning($"{response.StatusCode}: {requestUrl}");
                            logger.LogWarning($"   {response.Content}");
                        }
                    }
                };
            });

        }

        /// <summary>
        /// ADAL
        /// </summary>
        /// <param name="azureADB2COptions"></param>
        /// <returns>returns an access_token that represents the application's identity.</returns>
        private async Task<string> getAdTokenAsync(string azureAdSectionName = null)
        {
            azureAdSectionName = azureAdSectionName ?? AzureADDefaults.AuthenticationScheme;
            var adSection = Configuration.GetSection(azureAdSectionName) ?? Configuration.GetSection("AzureAD") ?? Configuration.GetSection("AzureAd");
            var clientId = adSection["ClientId"];
            if (string.IsNullOrWhiteSpace(clientId)) { throw new Exception($"require configuration for AzureAD.ClientId"); }
            var clientSecret = adSection["ClientSecret"];
            if (string.IsNullOrWhiteSpace(clientSecret)) { throw new Exception($"require configuration for AzureAD.ClientSecret"); }

            //var instance = adSection["Instance"];
            //if (string.IsNullOrWhiteSpace(instance)) { throw new Exception($"require configuration for AzureAD.Instance"); }

            var authContext = new AuthenticationContext(authority: adSection["Instance"]);
            var credential = new Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential(
                clientId: clientId,
                clientSecret: clientSecret
                );
            var authority = adSection["Authority"] ?? "https://graph.windows.net/";
            var authResult = await authContext.AcquireTokenAsync(resource: authority, clientCredential: credential);

            return authResult.AccessToken;
        }
    }
}
