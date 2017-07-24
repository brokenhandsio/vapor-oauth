# Vapor OAuth
Vapor OAuth is an OAuth2 Provider Library written for Vapor. You can integrate the library into your server to provide authorization for applications to connect to your APIs.

It follows both [RFC 6749](https://tools.ietf.org/html/rfc6749) and [RFC6750](https://tools.ietf.org/html/rfc6749) and there is an extensive test suite to make sure it adheres to the specification.

Vapor OAuth supports the standard grant types:

* Authorization Code
* Client Credentials
* Implcit Grant
* Password Credentials

For an excellent description on how the standard OAuth flows work, and what to expect when using and implementing them, have a look at https://www.oauth.com.

# Usage

## Getting Started

Vapor OAuth can be added to your Vapor add with a simple provider. To get started, first add the library to your `Package.swift` dependencies:

```swift
dependencies: [
    ...,
    .Package(url: "https://github.com/brokenhandsio/vapor-oauth", majorVersion: 0)
]
```

Next import the library into where you set up your `Droplet`:

```swift
import OAuth
```

Then add the provider to your `Config`:

```swift
try addProvider(OAuth.Provider(codeManager: MyCodeManager(), tokenManager: MyTokenManager(), clientRetriever: MyClientRetriever(), authorizeHandler: MyAuthHandler(), userManager: MyUserManager(), validScopes: ["view_profile", "edit_profile"]))
```

To integrate the library, you need to set up and number of things, which implement the various protocols required:

* `CodeManager` - this is responsible for generating and managing OAuth Codes. It is only required for the Authorization Code flow, so if you do not want to support this grant, you can leave out this parameter and use the default implementation
* `TokenManager` - this is responsible for generating and managing Access and Refresh Tokens. You can either store these in memory, in Fluent, or with any backend.
* `ClientRetriever` - this is responsible for getting all of the clients you want to support in your app. If you want to be able to dynamically add clients then you will need to make sure you can do that with your implementation. If you only want to support a set group of clients, you can use the `StaticClientRetriever` which is provided for you
* `AuthorizeHandler` - this is responsible for allowing users to allow/deny authorization requests. See below for more details. If you do not want to support this grant type you can exclude this parameter and use the default implementation
* `UserManager` - this is responsible for authenticating and getting users for the Password Credentials flow. If you do not want to support this flow, you can exclude this parameter and use the default implementation.
* `validScopes` - this is an optional array of scopes that you wish to support in your system.

Note that there are a number of default implementations for the different required protocols for Fluent in the [Vapor OAuth Fluent package](https://github.com/brokenhandsio/vapor-oauth-fluent).

The Provider will then register endpoints for authorization and tokens at `/oauth/authorize` and `/oauth/token`

## Protecting Endpoints

Vapor OAuth has a helper extension on `Request` to allow you to easily protect your API routes. For instance, let's say that you want to ensure that one route is accessed only with tokens with the `profile` scope, you can do:

```swift
try request.oauth.assertScopes(["profile"])
```

This will throw a 401 error if the token is not valid or does not contain the `profile` scope. This is so common, that there is a dedicated `OAuth2ScopeMiddleware` for this behaviour. You just need to initialise this with an array of scopes that must be required for that `protect` group. If you initialise it with a `nil` array, then it will just make sure that the token is valid.

You can also get the user with `try request.oauth.user()`.

# Grant Types

## Authorization Code Grant

The basic outline of this grant type is:

1. A client (another app) redirects a resource owner (a user that holds information with you) to your Vapor app.
2. Your Vapor app then authenticates the user and asks the user whether they want to allow the client access to the scopes requested (think logging into something with your Facebook account - it's this method).
3. If the user approves the application then the OAuth server redirects back to the client with an OAuth Code (that is typically valid for 60s or so)
4. The client can then exchange that code for an access and refresh token
5. The client can use the access token to make requests to the Resource Server (the OAuth server, or your web app)

### Implementation Details

As well as implementing the Code Manager, Token Manager, and Client Retriever, the most important part to implement is the `AuthorizeHandler`.

## Implicit Grant

## Resource Owner Password Credentials Grant

Note that if you are using the password flow, as per [the specification](https://tools.ietf.org/html/rfc6749#section-4.3.2), you must secure your endpoint against brute force attacks with rate limiting or generating alerts. The library will output a warning message to the console for any unauthorized attempts, which you can use for this purpose. The message is in the form of `LOGIN WARNING: Invalid login attempt for user <USERNAME>`.

## Client Credentials Grant
