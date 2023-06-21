using System.Text;
using Microsoft.InformationProtection;

AppConfig config = new ();
var clientId = config.GetClientId();
var appName = config.GetAppName();
var appVersion = config.GetAppVersion();

var appInfo = new ApplicationInfo()
{
    // ApplicationId should ideally be set to the same ClientId found in the Azure AD App Registration.
    // This ensures that the clientID in AAD matches the AppId reported in AIP Analytics.
    ApplicationId = clientId,
    ApplicationName = appName,
    ApplicationVersion = appVersion
};

var action = new Action(appInfo);

var templates = action.ListTemplates();

int i = 0;
foreach (var template in templates)
{
    Console.WriteLine("{0}: {1}", i.ToString(), template.Name);
    i++;
}

Console.WriteLine("");
// Console.WriteLine("Select a template: ");
// var selectedTemplate = Console.ReadLine();

// var publishHandler = action.CreatePublishingHandler(templates.ElementAt(int.Parse(selectedTemplate)).Id);

// Console.WriteLine("Enter some string to protect: ");
// var userInputString = Console.ReadLine();
// var userInputBytes = Encoding.UTF8.GetBytes(userInputString);

// var encryptedBytes = action.Protect(publishHandler, userInputBytes);
// Console.WriteLine("");
// Console.WriteLine("Encrypted bytes (UTF8): {0}", Encoding.UTF8.GetString(encryptedBytes));
// Console.WriteLine("Encrypted bytes (base64): {0}", Convert.ToBase64String(encryptedBytes));
// Console.WriteLine("");

// var serializedPublishingLicense = publishHandler.GetSerializedPublishingLicense();

// var consumeHandler = action.CreateConsumptionHandler(serializedPublishingLicense);

// var decryptedBytes = action.Unprotect(consumeHandler, encryptedBytes);

// Console.WriteLine("Decrypted content: {0}", Encoding.UTF8.GetString(decryptedBytes));

using (var stream = new FileStream(@"c:\kk\memoria.pdf", FileMode.Open, FileAccess.Read))
{
    var decryptedStream = await action.GetDecryptedStreamAsync(stream, "memoria.pdf");

    if (decryptedStream.Length == 0)
    {
        Console.WriteLine("Decrypted stream is empty.");
    }
    else
    {
        decryptedStream.Position = 0;
        using (var outputStream = new FileStream(@"c:\kk\memoria-un.pdf", FileMode.Create, FileAccess.Write))
        {
            decryptedStream.CopyTo(outputStream);
        }
    }
}

Console.WriteLine("Press a key to quit.");