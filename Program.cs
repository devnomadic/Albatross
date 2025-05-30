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
        sp.GetRequiredService<HttpClient>()
    )
);

// API access tokens are now hardcoded in the service for security purposes
// This makes them less discoverable than storing them in appsettings.json

await builder.Build().RunAsync();
