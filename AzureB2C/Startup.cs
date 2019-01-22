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
//using Microsoft.IdentityModel.Clients.ActiveDirectory;
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

            #region MyRegion
            //people are always not aware of case sensitivity
            var b2cConfig = Configuration.GetSection("AzureADB2C") ?? Configuration.GetSection("AzureAdB2C");
            services
                .AddAuthentication(AzureADB2CDefaults.AuthenticationScheme)
                .AddAzureADB2C(options => { b2cConfig.Bind(options); });

            //after: AddAzureADB2C
            var sp = services.BuildServiceProvider();
            var azureADB2COptions = sp.GetService<IOptionsMonitor<AzureADB2COptions>>().Get(AzureADB2CDefaults.AuthenticationScheme);

            ApiHelper.InitAsync(Configuration, "AzureAD").Wait();

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

                    var userId = context.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                    var claimsIdentity = (ClaimsIdentity)context.Principal.Identity;

                    string requestUrl = $"https://graph.microsoft.com/v1.0/users/{userId}/memberOf?$select=displayName";
                    var resObject = await ApiHelper.getApiASync(requestUrl);
                    var jo_groups = resObject["value"] as JArray;

                    foreach (var item in jo_groups)
                    {
                        var groupName = (string)item["displayName"];
                        claimsIdentity.AddClaim(new Claim(type: ClaimTypes.Role, value: groupName));
                    }

                };
            });

        }
    }
}
