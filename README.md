# Introduction
This is a library to implement an OAuth 2.0 resource server (RS). The library
can be used by any service that wants to accept OAuth 2.0 bearer tokens.

It is compatible with and was tested with 
[php-oauth](https://github.com/fkooman/php-oauth), and should work with Google.

# License
Licensed under the Apache License, Version 2.0;

   http://www.apache.org/licenses/LICENSE-2.0

# API
Using the library is straightforward:

    <?php
    require_once 'extlib/php-lib-remote-rs/lib/OAuth/RemoteResourceServer.php';

    use \OAuth\RemoteResourceServer as RemoteResourceServer;

    $config = array(
        "tokenInfoEndpoint" => "http://localhost/php-oauth/tokeninfo.php",
        "resourceServerRealm" => "My Demo Service",
        "throwException" => FALSE
    );

    $rs = new RemoteResourceServer($config);
    $rs->verifyRequest();

Only the `tokenInfoEndpoint` configuration parameter is required, the others
are optional:

* `tokenInfoEndpoint` - specify the location at which to verify the OAuth token;
* `resourceServerRealm` - specify the "realm" of the RS that is used when 
  returning errors to the client using the `WWW-Authenticate` header. Default 
  value is `Resource Server`;
* `throwException` - throw a `RemoteResourceServerException` instead of handling 
  the failure in the library by sending a response back to the client. This is 
  useful if you want to integrate the library in your own framework, you can
  use the information from the exception to craft your own response. Default
  value is `FALSE`.

## Verify Tokens
If you write a simple piece of software that does not use any framework for 
handling HTTP requests and responses you can use the following method to handle
all communication with the client by itself:

    verifyRequest()
    
This will extract the Bearer Authorization header or `access_token` query 
parameter, verify it at the authorization server and inform the client about
any problems.

If you use a HTTP framework some other methods are available to help you verfiy
tokens:

    verifyAuthorization($authorizationHeader, array $queryParameters)
    verifyAuthorizationHeader($authorizationHeader)
    verifyQueryParameter(array $queryParameters)
    
The `verifyAuthorization` method can check both the HTTP `Authorization` header 
value and the query parameters, in particular the `access_token` query 
parameter.

The `verifyAuthorizationHeader` method checks just feed the `Authorization` 
header.

The `verifyQueryParameter` method will check the query parameters that are 
provided.

If you use a framework, also make sure to set the `throwException` field to 
`TRUE` and catch the `RemoteResourceOwnerException` exception and deal with 
it accordingly.

## Retrieve Resource Owner Information
After the `verifyRequest()`, or any of the other verify functions, some methods 
are available to retrieve information about the resource owner and client 
assuming the verification was successful.

* `getResourceOwnerId()` (the unique resource owner identifier)
* `getAttributes()` (additional attributes associated with the resource owner)
* `getScope()` (the scope granted to the client accessing this resource)
* `getEntitlement()` (the entitlement the resource owner has when accessing this 
  resource)

Note that the `getAttributes()` and `getEntitlement()` methods are not supported
by all authorization servers and is a properietary extension to 
[https://github.com/fkooman/php-oauth](php-oauth).