<p align="center">
    <img src="https://user-images.githubusercontent.com/9938337/29741272-2c09fb0e-8a61-11e7-8697-0ce963bc4b5a.png" alt="Vapor OAuth">
    <br>
    <br>
    <a href="https://swift.org">
        <img src="http://img.shields.io/badge/Swift-5.7-brightgreen.svg" alt="Language">
    </a>
    <a href="https://github.com/brokenhandsio/vapor-oauth/actions/workflows/main.yml">
        <img src="https://github.com/brokenhandsio/vapor-oauth/actions/workflows/main.yml/badge.svg" alt="Test Status">
    </a>
    <a href="https://codecov.io/gh/brokenhandsio/vapor-oauth">
        <img src="https://codecov.io/gh/brokenhandsio/vapor-oauth/branch/master/graph/badge.svg" alt="Code Coverage">
    </a>
    <a href="https://raw.githubusercontent.com/brokenhandsio/vapor-oauth/master/LICENSE">
        <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License">
    </a>
</p>

Vapor OAuth is an OAuth2 Provider Library written for Vapor. You can integrate the library into your server to provide authorization for applications to connect to your APIs.

It follows both [RFC 6749](https://tools.ietf.org/html/rfc6749) and [RFC6750](https://tools.ietf.org/html/rfc6750) and there is an extensive test suite to make sure it adheres to the specification.

It also implements the [RFC 7662](https://tools.ietf.org/html/rfc7662) specification for Token Introspection, which is useful for microservices with a shared, central authorization server.

Vapor OAuth supports the standard grant types:

* Authorization Code
* Client Credentials
* Implicit Grant
* Password Credentials

For an excellent description on how the standard OAuth flows work, and what to expect when using and implementing them, have a look at https://www.oauth.com.

# Usage

## Getting Started

Vapor OAuth can be added to your Vapor add with a simple provider. To get started, first add the library to your `Package.swift` dependencies:

```swift
dependencies: [
    ...,
    .package(url: "https://github.com/brokenhandsio/vapor-oauth", from: "0.6.0"))
]
```

Next import the library into where you set up your `Droplet`:

```swift
import VaporOAuth
```

Then add the provider to your `Config`:

```swift
try addProvider(VaporOAuth.Provider(codeManager: MyCodeManager(), tokenManager: MyTokenManager(), clientRetriever: MyClientRetriever(), authorizeHandler: MyAuthHandler(), userManager: MyUserManager(), validScopes: ["view_profile", "edit_profile"], resourceServerRetriever: MyResourceServerRetriever()))
```

To integrate the library, you need to set up a number of things, which implement the various protocols required:

* `CodeManager` - this is responsible for generating and managing OAuth Codes. It is only required for the Authorization Code flow, so if you do not want to support this grant, you can leave out this parameter and use the default implementation
* `TokenManager` - this is responsible for generating and managing Access and Refresh Tokens. You can either store these in memory, in Fluent, or with any backend.
* `ClientRetriever` - this is responsible for getting all of the clients you want to support in your app. If you want to be able to dynamically add clients then you will need to make sure you can do that with your implementation. If you only want to support a set group of clients, you can use the `StaticClientRetriever` which is provided for you
* `AuthorizeHandler` - this is responsible for allowing users to allow/deny authorization requests. See below for more details. If you do not want to support this grant type you can exclude this parameter and use the default implementation
* `UserManager` - this is responsible for authenticating and getting users for the Password Credentials flow. If you do not want to support this flow, you can exclude this parameter and use the default implementation.
* `validScopes` - this is an optional array of scopes that you wish to support in your system.
* `ResourceServerRetriever` - this is only required if using the Token Introspection Endpoint and is what is used to authenticate resource servers trying to access the endpoint

Note that there are a number of default implementations for the different required protocols for Fluent in the [Vapor OAuth Fluent package](https://github.com/brokenhandsio/vapor-oauth-fluent).

The Provider will then register endpoints for authorization and tokens at `/oauth/authorize` and `/oauth/token`

## Protecting Endpoints

Vapor OAuth has a helper extension on `Request` to allow you to easily protect your API routes. For instance, let's say that you want to ensure that one route is accessed only with tokens with the `profile` scope, you can do:

```swift
try request.oauth.assertScopes(["profile"])
```

This will throw a 401 error if the token is not valid or does not contain the `profile` scope. This is so common, that there is a dedicated `OAuth2ScopeMiddleware` for this behaviour. You just need to initialise this with an array of scopes that must be required for that `protect` group. If you initialise it with a `nil` array, then it will just make sure that the token is valid.

You can also get the user with `try request.oauth.user()`.

### Protecting Resource Servers With Remote Auth Server

If you have resource servers that are not the same server as the OAuth server that you wish to protect using the Token Introspection Endpoint, things are slightly different. See the [Token Introspection](#token-introspection) section for more information.

# Grant Types

## Authorization Code Grant

The Authorization Code flow is the most common flow used with OAuth. It is what most web applications will use for authorization with an OAuth Resource Server. The basic outline of this grant type is:

1. A client (another app) redirects a resource owner (a user that holds information with you) to your Vapor app.
2. Your Vapor app then authenticates the user and asks the user whether they want to allow the client access to the scopes requested (think logging into something with your Facebook account - it's this method).
3. If the user approves the application then the OAuth server redirects back to the client with an OAuth Code (that is typically valid for 60s or so)
4. The client can then exchange that code for an access and refresh token
5. The client can use the access token to make requests to the Resource Server (the OAuth server, or your web app)

### Implementation Details

As well as implementing the Code Manager, Token Manager, and Client Retriever, the most important part to implement is the `AuthorizeHandler`. Your authorize handler is responsible for letting the user decide whether they should let an application have access to their account. It should be [clear and easy](https://www.oauth.com/oauth2-servers/authorization/the-authorization-interface/) to understand what is going on and should be clear what the application is requesting access to.

It is your responsibility to ensure that the user is logged in and handling the case when they are not. An example implementation for the authorize handler may look something like:

```swift
func handleAuthorizationRequest(_ request: Request, authorizationGetRequestObject: AuthorizationGetRequestObject) throws -> ResponseRepresentable {
    guard request.auth.isAuthenticated(FluentOAuthUser.self) else {
        let redirectCookie = Cookie(name: "OAuthRedirect", value: request.uri.description)
        let response = Response(redirect: "/login")
        response.cookies.insert(redirectCookie)
        return response
    }

    var parameters = Node([:], in: nil)
    let client = clientRetriever.getClient(clientID: authorizationGetRequestObject.clientID)

    try parameters.set("csrf_token", authorizationGetRequestObject.csrfToken)
    try parameters.set("scopes", authorizationGetRequestObject.scopes)
    try parameters.set("client_name", client.clientName)
    try parameters.set("client_image", client.clientImage)
    try parameters.set("user", request.auth.user)

    return try view.make("authorizeApplication", parameters)
}
```

You need to add the [`SessionsMiddleware`](https://docs.vapor.codes/2.0/sessions/sessions/) to your application for this flow to complete in order for the CSRF protection to work.

When submitting the authorize form back to Vapor OAuth, in the form data it must include:

* `applicationAuthorized` - a boolean value to signify if the user allowed access to the client or not
* `csrfToken` - the CSRF token supplied in the handler to protect against CSRF attacks

## Implicit Grant

The Implicit Grant is almost identical to the Authorize Code flow, except instead of being redirected back with a code which you then exchange for a token, you get redirected back with the token in the fragment. It is up to the client (such as an iOS application) to then parse the token out of the redirect URI fragment.

This flow was designed for clients where you couldn't guarantee the security of the client secret, client-side apps, but has fallen out of favour recently and it is generally recommended to use the Authorization Code flow without a client secret instead.

## Resource Owner Password Credentials Grant

The Password Credentials flow should only be used for first party applications, and Vapor OAuth mandates this. This flow allows the client to collect the username and password of the user and submit them directly to the OAuth server to get a token.

Note that if you are using the password flow, as per [the specification](https://tools.ietf.org/html/rfc6749#section-4.3.2), you must secure your endpoint against brute force attacks with rate limiting or generating alerts. The library will output a warning message to the console for any unauthorized attempts, which you can use for this purpose. The message is in the form of `LOGIN WARNING: Invalid login attempt for user <USERNAME>`.

## Client Credentials Grant

Client Credentials is a userless flow and is designed for servers accessing other servers without the need for a user. Access is granted based upon the authentication of the client requesting access.

## Token Introspection

If running a microservices architecture it is useful to have a single server that handles authorization, which all the other resource servers query. To do this, you can use the Token Introspection Endpoint extension. In Vapor OAuth, this adds an endpoint you can post tokens tokens at `/oauth/token_info`.

You can send a POST request to this endpoint with a single parameter, `token`, which contains the OAuth token you want to check. If it is valid and active, then it will return a JSON payload, that looks similar to:

```json
{
    "active": true,
    "client_id": "ABDED0123456",
    "scope": "email profile",
    "exp": 1503445858,
    "user_id": "12345678",
    "username": "hansolo",
    "email_address": "hansolo@therebelalliance.com"
}
```

If the token has expired or does not exist then it will simply return:

```json
{
    "active": false
}
```

This endpoint is protected using HTTP Basic Authentication so you need to send an `Authorization: Basic abc` header with the request. This will check the `ResourceServerRetriever` for the username and password sent.

**Note:** as per [the spec](https://tools.ietf.org/html/rfc7662#section-4) - the token introspection endpoint MUST be protected by HTTPS - this means the server must be behind a TLS certificate (commonly known as SSL). Vapor OAuth leaves this up to the integrating library to implement.

### Protecting Endpoints

To protect resources on other servers with OAuth using the Token Introspection endpoint, you either need to use the `OAuth2TokenIntrospectionMiddleware` on your routes that you want to protect, or you need to manually set up the `Helper` object (the middleware does this for you). Both the middleware and helper setup require:

* `tokenIntrospectionEndpoint` - the endpoint where the token can be validated
* `client` - the `Droplet`'s client to send the token validation request with
* `resourceServerUsername` - the username of the resource server
* `resourceServerPassword` - the password of the resource server

Once either of these has been set up, you can then call `request.oauth.user()` or `request.oauth.assertScopes()` like normal.
