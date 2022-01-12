﻿using AADLab.Controllers;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace AADLab.Services
{
    public class Graph
    {
        public class GraphToken
        {
            public string Token { get; set; }
            public DateTimeOffset Expires { get; set; }

            public bool IsExpired() => Expires <= DateTime.UtcNow.AddSeconds(-30);
        }

        static Dictionary<string, GraphToken> _fakeCache = new(StringComparer.OrdinalIgnoreCase);

        private readonly IConfiguration _configuration;

        private HttpClient _httpClient = new();

        public Graph(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public void RemoveTokenForUser(string userId)
        {
            _fakeCache.Remove(userId);
        }

        public async Task<string> GetOnBehalfOfToken(string token)
        {
            var builder = ConfidentialClientApplicationBuilder.Create(_configuration["Msal:ClientId"])
                .WithClientSecret(_configuration["Msal:ClientSecret"]);

            var client = builder.Build();

            //Calls the /oauth2/v2.0/token endpoint to swap the given AAD token for another with different scopes
            var tokenBuilder = client.AcquireTokenOnBehalfOf(new[] { "User.Read" }, new UserAssertion(token));

            var result = await tokenBuilder.ExecuteAsync();

            return result.AccessToken;
        }

        public async Task<GraphMeResult> GetMe(string token)
        {
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var meResult = await _httpClient.GetAsync("https://graph.microsoft.com/v1.0/me");

            return JsonSerializer.Deserialize<GraphMeResult>(await meResult.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }

        public async Task<GraphOrganizationResult> GetOrganisation(string token)
        {
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var orgResult = await _httpClient.GetAsync("https://graph.microsoft.com/v1.0/organization");

            return JsonSerializer.Deserialize<GraphOrganizationResult>(await orgResult.Content.ReadAsStringAsync(), new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }
    }
}
