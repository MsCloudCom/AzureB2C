using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace AzureB2C
{
    public class ApiHelper
    {
        private static HttpClient httpClient;
        public static async Task InitAsync(IConfiguration configuration, string azureAdSectionName = null)
        {
            var accessToken = await getAdTokenAsync(configuration, azureAdSectionName);
            httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        public static async Task<JObject> getApiASync(string apiUrl)
        {
            var response = await httpClient.GetAsync(apiUrl);
            var content = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                return JObject.Parse(content);
            }
            else
            {
                //Logger.LogError($"{response.StatusCode}: {apiUrl}");
                //logger.LogError($"   {response.Content}");
                throw new Exception($"{response.StatusCode} for {apiUrl}");
            }

        }

        private static async Task<string> getAdTokenAsync(IConfiguration configuration, string azureAdSectionName = null)
        {

            azureAdSectionName = azureAdSectionName ?? AzureADDefaults.AuthenticationScheme;
            var adSection = configuration.GetSection(azureAdSectionName) ?? configuration.GetSection("AzureAD") ?? configuration.GetSection("AzureAd");
            var adOptions = new AzureADOptions();
            adSection.Bind(adOptions);


            var clientId = adSection["ClientId"];
            if (string.IsNullOrWhiteSpace(clientId)) { throw new Exception($"require configuration for AzureAD.ClientId"); }
            var clientSecret = adSection["ClientSecret"];
            if (string.IsNullOrWhiteSpace(clientSecret)) { throw new Exception($"require configuration for AzureAD.ClientSecret"); }

            //var instance = adSection["Instance"];
            //if (string.IsNullOrWhiteSpace(instance)) { throw new Exception($"require configuration for AzureAD.Instance"); }
            string[] scopes = new string[] { "https://graph.microsoft.com/.default" };
            var credential = new ClientCredential(secret: clientSecret);
            var authority = adSection["Instance"] ?? "https://graph.windows.net/";
            var authContext = new ConfidentialClientApplication(
                clientId: clientId,
                authority: authority,
                redirectUri: "http://daemon",
                clientCredential: credential,
                userTokenCache: null,
                appTokenCache: new TokenCache()
                );
            try
            {
                var authResult = await authContext.AcquireTokenForClientAsync(scopes);
                return authResult.AccessToken;

            }
            catch (MsalServiceException ex)
            {
                // Case when ex.Message contains:
                // AADSTS70011 Invalid scope. The scope has to be of the form "https://resourceUrl/.default"
                // Mitigation: change the scope to be as expected
                //logger.LogError($"getAdTokenAsync: {ex.Message}");
                throw;
            }

        }
    }
}
