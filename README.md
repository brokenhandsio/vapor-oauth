# Vapor OAuth
Vapor OAuth is an OAuth2 Provider Library written for Vapor. You can integrate the library into your server to provide authorization for applications to connect to your APIs.

It follows both [RFC 6749](https://tools.ietf.org/html/rfc6749) and [RFC6750](https://tools.ietf.org/html/rfc6749) and there is an extensive test suite to make sure it adheres to the specification.

**COMING SOON**

# USAGE

## Resource Owner Password Credentials Grant

Note that if you are using the password flow, as per [the specification](https://tools.ietf.org/html/rfc6749#section-4.3.2), you must secure your endpoint against brute force attacks with rate limiting or generating alerts. The library will output a warning message to the console for any unauthorized attempts, which you can use for this purpose. The message is in the form of `LOGIN WARNING: Invalid login attempt for user <USERNAME>`.
