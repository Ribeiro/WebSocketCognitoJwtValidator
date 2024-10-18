using System.IdentityModel.Tokens.Jwt;
using System.Net.WebSockets;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.WebSockets;
using System.Text;
using Microsoft.AspNetCore.Http;
using WebSocketCognitoJwtValidator.Constants;
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);

ConcurrentDictionary<string, IList<SecurityKey>> signingKeysCache = new();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = AppConstants.validIssuer,
            ValidAudience = AppConstants.audience,
            IssuerSigningKeyResolver = (string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters) =>
            {
                if (!signingKeysCache.TryGetValue(validationParameters.ValidIssuer, out var signingKeys))
                {
                    throw new SecurityTokenException("Unable to retrieve signing keys");
                }

                return signingKeys;
            }
        };
    });

builder.Services.AddWebSockets(options =>
{
    options.KeepAliveInterval = TimeSpan.FromSeconds(120);
});

var app = builder.Build();

app.UseAuthentication();
app.UseWebSockets();

app.Map("/ws", async (HttpContext context) =>
{
    if (context.WebSockets.IsWebSocketRequest)
    {
        using WebSocket webSocket = await context.WebSockets.AcceptWebSocketAsync();
        await HandleWebSocketConnection(webSocket);
    }
    else
    {
        context.Response.StatusCode = 400;
    }
});

// Carrega as chaves assinantes de forma assíncrona no início
await CacheSigningKeysAsync(AppConstants.validIssuer);

await app.RunAsync();

async Task HandleWebSocketConnection(WebSocket webSocket)
{
    var buffer = new byte[1024 * 4];
    WebSocketReceiveResult result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);

    while (result.MessageType != WebSocketMessageType.Close)
    {
        string message = Encoding.UTF8.GetString(buffer, 0, result.Count);
        string token = ExtractTokenFromMessage(message);
        bool isValid = await ValidateTokenAsync(token);
        string responseMessage = isValid ? "Token is valid." : "Token is invalid.";

        var responseBuffer = Encoding.UTF8.GetBytes(responseMessage);
        await webSocket.SendAsync(new ArraySegment<byte>(responseBuffer), WebSocketMessageType.Text, true, CancellationToken.None);
        result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
    }

    await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", CancellationToken.None);
}

string ExtractTokenFromMessage(string message)
{
    var json = JsonDocument.Parse(message);
    if (json.RootElement.TryGetProperty("token", out JsonElement tokenElement) && tokenElement.ValueKind == JsonValueKind.String)
    {
        return tokenElement.GetString()!;
    }

    throw new InvalidDataException("Missing JWT Token");
}

async Task<bool> ValidateTokenAsync(string token)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    try
    {
        return await Task.Run(() =>
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidIssuer = AppConstants.validIssuer,
                ValidateAudience = true,
                ValidAudience = AppConstants.audience,
                ValidateLifetime = true
            }, out _);

            return true;
        });
    }
    catch
    {
        return false;
    }
}

async Task CacheSigningKeysAsync(string issuer)
{
    using (var httpClient = new HttpClient())
    {
        var json = await httpClient.GetStringAsync($"{issuer}/.well-known/jwks.json");
        var jsonDoc = JsonDocument.Parse(json);
        var keys = new List<SecurityKey>();

        foreach (var element in jsonDoc.RootElement.GetProperty("keys").EnumerateArray())
        {
            var key = new JsonWebKey
            {
                Kty = element.GetProperty("kty").GetString(),
                E = element.GetProperty("e").GetString(),
                N = element.GetProperty("n").GetString(),
                Kid = element.GetProperty("kid").GetString()
            };

            keys.Add(key);
        }

        signingKeysCache[issuer] = keys;
    }
}