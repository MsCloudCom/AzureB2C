using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureADB2C.UI;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AzureB2C
{
    public class Startup
    {
        private readonly ILogger<Startup> logger;

        public Startup(IConfiguration configuration, ILogger<Startup> logger)
        {
            Configuration = configuration;
            this.logger = logger;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {

                options.CheckConsentNeeded = context => true;// This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            //people are always not aware of case sensitivity
            var b2cSettingsSection = Configuration.GetSection("AzureADB2C") ?? Configuration.GetSection("AzureAdB2C");
            services.AddAuthentication(AzureADB2CDefaults.AuthenticationScheme)
                .AddAzureADB2C(options => b2cSettingsSection.Bind(options));

            #region MyRegion

            AddRole_AadApi(services);

            #region fix-AccessDenied wrong path
            services.Configure<CookieAuthenticationOptions>(AzureADB2CDefaults.CookieScheme, options =>
            {
                options.AccessDeniedPath = "/AzureADB2C/Account/AccessDenied";
            });
            #endregion


            #endregion


            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
        }
        /// <summary>
        /// Fetch AD Groups (using Azure AD Graph web api) after authenticated in B2C
        /// </summary>
        /// <param name="services"></param>
        /// 
        //[Obsolete("Use AddRoleFromAd_MicrosoftGraphApi, which uses Microsoft Graph web api")]
        private void AddRole_AadApi(IServiceCollection services)
        {
            services.Configure<OpenIdConnectOptions>(AzureADB2CDefaults.OpenIdScheme, options =>
            {
                options.Events.OnTokenValidated = async context =>
                {
                    if (context.SecurityToken is JwtSecurityToken token) //wjp:lession
                    {
                        if (context.Principal.Identity is ClaimsIdentity identity)
                        {
                            var authContext = new AuthenticationContext(authority: Configuration["AzureAd:Instance"]);
                            var credential = new ClientCredential(clientId: Configuration["AzureAd:ClientId"], clientSecret: Configuration["AzureAd:ClientSecret"]);

                            //ADAL then returns an access_token that represents the application's identity.
                            var authority = "https://graph.windows.net/";
                            var authResult = await authContext.AcquireTokenAsync(authority, credential);

                            var b2c_user_id = token.Subject;
                            var domain = Configuration["AzureAd:Domain"]; // azureADOptions.Domain;
                            string url = $"https://graph.windows.net/{domain}/users/{b2c_user_id}/memberOf?api-version=1.6";
                            var httpClient = new HttpClient();
                            var request = new HttpRequestMessage(HttpMethod.Get, url);
                            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authResult.AccessToken);
                            var response = await httpClient.SendAsync(request);

                            var content = await response.Content.ReadAsStringAsync();

                            var jsonSettings = new JsonSerializerSettings() { Formatting = Formatting.Indented, };

                            var formatted = JObject.Parse(content);
                            var jo_groups = formatted["value"] as JArray;

                            var claimsIdentity = (ClaimsIdentity)context.Principal.Identity;

                            foreach (var item in jo_groups)
                            {
                                var groupName = (string)item["displayName"];
                                claimsIdentity.AddClaim(new Claim(type: ClaimTypes.Role, value: groupName));
                            }
                            logger.LogDebug(JsonConvert.SerializeObject(formatted, Formatting.Indented));
                        }
                    }
                };
            });

        }

        /// <summary>
        /// Fetch AD Groups (using ActiveDirectoryClient) after authenticated in B2C
        /// </summary>
        /// <param name="services"></param>
        /// 
        [Obsolete("Use AddRole_MicrosoftGraphApi, which uses Microsoft Graph web api")]
        private void AddRoled_ActiveDirectoryClient(IServiceCollection services)
        {
            services.Configure<OpenIdConnectOptions>(AzureADB2CDefaults.OpenIdScheme, options =>
            {
                options.Events.OnTokenValidated = async context =>
                {
                    if (context.SecurityToken is JwtSecurityToken b2c_token) //wjp:lession
                    {
                        var b2c_user_id = b2c_token.Subject;
                        var claimsIdentity = (ClaimsIdentity)context.Principal.Identity;
                        if (context.Principal.Identity is ClaimsIdentity identity)
                        {
                            var adSettings = Configuration.GetSection("AzureAD") ?? Configuration.GetSection("AzureAd");

                            var authContext = new AuthenticationContext(authority: adSettings["Instance"]);
                            var credential = new ClientCredential(clientId: adSettings["ClientId"], clientSecret: adSettings["ClientSecret"]);

                            //ADAL then returns an access_token that represents the application's identity.
                            var authority = "https://graph.windows.net/";
                            var adAuthResult = await authContext.AcquireTokenAsync(authority, credential);

                            Uri serviceRoot = new Uri(new Uri("https://graph.windows.net"), adSettings["Domain"]);
                            var adClient = new ActiveDirectoryClient(serviceRoot, async () => await Task.FromResult(adAuthResult.AccessToken));
                            var adUser =(User) await adClient.Users.Where(user => user.ObjectId == b2c_user_id).ExecuteSingleAsync();
                            var userFetcher = (IUserFetcher)adUser;
                            var groupPage = await userFetcher.MemberOf.ExecuteAsync();

                            var adGroups = new List<Group>();
                            while (groupPage != null)
                            {
                                foreach (var item in groupPage.CurrentPage)
                                {
                                    if(item is Group group)
                                    {
                                        adGroups.Add(group);
                                        claimsIdentity.AddClaim(new Claim(type: ClaimTypes.Role, value: group.DisplayName));
                                    }
                                }
                                groupPage = await groupPage.GetNextPageAsync();
                            }


                            logger.LogDebug("ad auth:");
                        }
                    }
                };
            });

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
    }
}
