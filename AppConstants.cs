namespace WebSocketCognitoJwtValidator.Constants
{
    public static class AppConstants
    {
        public const string region = "us-east-1";
        public const string userPoolId = "1234526879";
        public const string audience = "aud1234526879";
        public const string validIssuer = $"https://cognito-idp.{region}.amazonaws.com/{userPoolId}";
    }
}