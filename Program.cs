using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Albatross;
using Albatross.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
builder.Services.AddScoped<AbuseIPDBService>(sp => 
    new AbuseIPDBService(
        sp.GetRequiredService<HttpClient>(), 
        sp.GetRequiredService<IConfiguration>()
    )
);

// Set API access token through appsettings.json, environment variables or a server auth endpoint
// For development, you can add this to appsettings.Development.json
// In production, consider using a server API endpoint to get the token securely

await builder.Build().RunAsync();
