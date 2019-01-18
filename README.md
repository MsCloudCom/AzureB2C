Azure B2C Sample Starter-kit
============

ASP.NET Core Web Application, Azure AD B2C as IdP, Azure Active Directory as Role authorization source.

## Prequisites
1. Azure Account to log in Azure Portal;
2. create your pay-as-you-go Subscription; (it won't charge you for this sample);
3. create a B2C tenant(name: myB2cTenant), ClientId, ClientSecret;(choose Social and local accounts (Azure AD B2C));
4. add a new Azure AD B2C - Applications (name: myB2cApp); 
5. set Properties > Reply URL list, add https://localhost:5001/signin-oidc and https://localhost:44333/signin-oidc
6. create a group in AD, name: myB2cRole-PowerUserRole (do not add users);
7. add a new AD application with permissions "Read and write directory data", get your AD ClientId, ClientSecret;
8. configure appsettings.json, note: for security concern, you should set your AD and B2C client secret values to environment variables or secret.json file. (replace double-quatation with two, if any)
   * C:\> setx "AzureAd:ClientSecret" "Your_AD_Secret"
   * C:\> setx "AzureADB2C:ClientSecret" "Your_B2C_Secret"

## Run the Sample

* C:\Users\Username\source\repos\> git clone  https://github.com/MsCloudCom/Azure-B2C-Sample.git
* Open the solution in Visual Studio
* configure appsettings.json
* press Ctrl+F5 to run the application
* click "Sign in" link to sign up your account; 


## Manage group in Azure
go to Azure AD, assign the new user to the group myB2cRole-PowerUserRole;


## Code of conduct
See commits for each step.

