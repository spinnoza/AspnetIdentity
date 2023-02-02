### 1.JWT 格式的 Authentication

~~~c#
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, config =>
    {
        var secretBytes = Encoding.UTF8.GetBytes(Constants.Secret);
        var key = new SymmetricSecurityKey(secretBytes);

        config.Events = new JwtBearerEvents()
        {
            OnMessageReceived = context =>
            {
                if (context.Request.Query.ContainsKey("access_token"))
                {
                    context.Token = context.Request.Query["access_token"];
                }

                return Task.CompletedTask;
            }
        };

        config.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidIssuer = Constants.Issuer,
            ValidAudience = Constants.Audiance,
            IssuerSigningKey = key,
        };
    });
~~~



~~~ c#
   public IActionResult Authenticate()
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "some_id"),
                new Claim("granny", "cookie")
            };

            var secretBytes = Encoding.UTF8.GetBytes(Constants.Secret);
            var key = new SymmetricSecurityKey(secretBytes);
            var algorithm = SecurityAlgorithms.HmacSha256;

            var signingCredentials = new SigningCredentials(key, algorithm);

            var token = new JwtSecurityToken(
                Constants.Issuer,
                Constants.Audiance,
                claims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddHours(1),
                signingCredentials);

            var tokenJson = new JwtSecurityTokenHandler().WriteToken(token);

            return Ok(new { access_token = tokenJson });
        }
~~~





### 2.oauth2.0  Authorization Code Grant

**Client**

~~~ c#
builder.Services.AddAuthentication(config => {
        // We check the cookie to confirm that we are authenticated
        config.DefaultAuthenticateScheme = "ClientCookie";
        // When we sign in we will deal out a cookie
        config.DefaultSignInScheme = "ClientCookie";
        // use this to check if we are allowed to do something.
        config.DefaultChallengeScheme = "OurServer";
    })
    .AddCookie("ClientCookie")
    .AddOAuth("OurServer", config => {
        config.ClientId = "client_id";
        config.ClientSecret = "client_secret";
         config.CallbackPath = new PathString("/authorization-code/callback");
        config.AuthorizationEndpoint = "https://localhost:7265/oauth/authorize";
        config.TokenEndpoint = "https://localhost:7265/oauth/token";

        config.SaveTokens = true;

        config.Events = new OAuthEvents()
        {
            OnCreatingTicket = context =>
            {
                var accessToken = context.AccessToken;
                if (accessToken!=null)
                {
                    var base64payload = accessToken.Split('.')[1];
                    var bytes = Convert.FromBase64String(base64payload);
                    var jsonPayload = Encoding.UTF8.GetString(bytes);
                    var claims = JsonConvert.DeserializeObject<Dictionary<string, string>>(jsonPayload);

                    foreach (var claim in claims)
                    {
                        context.Identity?.AddClaim(new Claim(claim.Key, claim.Value));
                    }

                   
                }

                return Task.CompletedTask;

            }
        };
    });
~~~



**Server**

~~~c#
 public class OAuthController : Controller
    {
        [HttpGet]
        public IActionResult Authorize(
            string response_type, // authorization flow type 
            string client_id, // client id
            string redirect_uri,
            string scope, // what info I want = email,grandma,tel
            string state) // random string generated to confirm that we are going to back to the same client
        {
            // ?a=foo&b=bar
            var query = new QueryBuilder();
            query.Add("redirectUri", redirect_uri);
            query.Add("state", state);

            return View(model: query.ToString());
        }

        [HttpPost]
        public IActionResult Authorize(
            string username,
            string redirectUri,
            string state)
        {
            const string code = "BABAABABABA";

            var query = new QueryBuilder();
            query.Add("code", code);
            query.Add("state", state);


            return Redirect($"{redirectUri}{query.ToString()}");
        }

        public async Task<IActionResult> Token(
            string grant_type, // flow of access_token request
            string code, // confirmation of the authentication process
            string redirect_uri,
            string client_id)
        {
            // some mechanism for validating the code

            var claims = new[]
          {
                new Claim(JwtRegisteredClaimNames.Sub, "some_id"),
                new Claim("granny", "cookie")
            };

            var secretBytes = Encoding.UTF8.GetBytes(Constants.Secret);
            var key = new SymmetricSecurityKey(secretBytes);
            var algorithm = SecurityAlgorithms.HmacSha256;

            var signingCredentials = new SigningCredentials(key, algorithm);

            var token = new JwtSecurityToken(
                Constants.Issuer,
                Constants.Audiance,
                claims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddHours(1),
                signingCredentials);

            var access_token = new JwtSecurityTokenHandler().WriteToken(token);

            var responseObject = new
            {
                access_token,
                token_type = "Bearer",
                raw_claim = "oauthTutorial"
            };

            var responseJson = JsonConvert.SerializeObject(responseObject);

            return new JsonResult(responseObject);
        }
    }
~~~









