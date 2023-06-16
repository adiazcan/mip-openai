using Microsoft.Identity.Client;
using Microsoft.InformationProtection;

public class AuthDelegateImpl : IAuthDelegate
{
    AppConfig config = new ();

    private static bool isMultitenantApp;
    private static string tenant;
    private ApplicationInfo appInfo;

    // Microsoft Authentication Library IPublicClientApplication
    private IPublicClientApplication _app;

    // Define MSAL scopes.
    // As of the 1.7 release, the two services backing the MIP SDK, RMS and MIP Sync Service, provide resources instead of scopes.
    // The List<string> entities below will be used to map the resources to scopes and to pass those scopes to Azure AD via MSAL.

    public AuthDelegateImpl(ApplicationInfo appInfo)
    {
        //redirectUri = config.GetRedirectUri();        
        isMultitenantApp = Convert.ToBoolean(config.GetIsMultiTenantApp());
        tenant = config.GetTenantId();
        this.appInfo = appInfo;
    }

    /// <summary>
    /// AcquireToken is called by the SDK when auth is required for an operation. 
    /// Adding or loading an IFileEngine is typically where this will occur first.
    /// The SDK provides all three parameters below.Identity from the EngineSettings.
    /// Authority and resource are provided from the 401 challenge.
    /// The SDK cares only that an OAuth2 token is returned.How it's fetched isn't important.
    /// In this sample, we fetch the token using Active Directory Authentication Library(ADAL).
    /// </summary>
    /// <param name="identity"></param>
    /// <param name="authority"></param>
    /// <param name="resource"></param>
    /// <returns>The OAuth2 token for the user</returns>
    public string AcquireToken(Identity identity, string authority, string resource, string claims)
    {
        return AcquireTokenAsync(authority, resource, claims, isMultitenantApp).Result.AccessToken;
    }

    /// <summary>
    /// Implements token acquisition logic via the Microsoft Authentication Library.
    /// 
    /// /// </summary>
    /// <param name="identity"></param>
    /// <param name="authority"></param>
    /// <param name="resource"></param>
    /// <param name="claims"></param>
    /// <returns></returns>
    public async Task<AuthenticationResult> AcquireTokenAsync(string authority, string resource, string claims, bool isMultiTenantApp = true)
    {
        AuthenticationResult result = null;

        // Create an auth context using the provided authority and token cache
        if (_app == null)
        {
            if (isMultitenantApp)
                _app = PublicClientApplicationBuilder.Create(appInfo.ApplicationId)
                    .WithAuthority(authority)
                    .WithDefaultRedirectUri()
                    .Build();
            else
            {
                if (authority.ToLower().Contains("common"))
                {
                    var authorityUri = new Uri(authority);
                    authority = String.Format("https://{0}/{1}", authorityUri.Host, tenant);
                }
                _app = PublicClientApplicationBuilder.Create(appInfo.ApplicationId)
                    .WithAuthority(authority)
                    .WithDefaultRedirectUri()
                    .Build();

            }
        }
        var accounts = await _app.GetAccountsAsync();//).GetAwaiter().GetResult();

        // Append .default to the resource passed in to AcquireToken().
        string[] scopes = new string[] { resource[resource.Length - 1].Equals('/') ? $"{resource}.default" : $"{resource}/.default" };

        try
        {
            result = await _app.AcquireTokenSilent(scopes, accounts.FirstOrDefault())
                .ExecuteAsync();
        }

        catch (MsalUiRequiredException ex)
        {
            System.Console.WriteLine(ex.Message);
            result = _app.AcquireTokenInteractive(scopes)
                .ExecuteAsync()
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();
        }

        // Return the token. The token is sent to the resource.                           
        return result;
    }

    /// <summary>
    /// The GetUserIdentity() method is used to pre-identify the user and obtain the UPN. 
    /// The UPN is later passed set on FileEngineSettings for service location.
    /// </summary>
    /// <returns>Microsoft.InformationProtection.Identity</returns>
    public Identity GetUserIdentity()
    {
        AuthenticationResult result = AcquireTokenAsync("https://login.microsoftonline.com/common", "https://graph.microsoft.com", null).Result;
        return new Identity(result.Account.Username);
    }
}