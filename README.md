# Introduction
This is a library to implement an OAuth 2.0 resource server (RS). The library
can be used by any service that wants to accept OAuth 2.0 bearer tokens.

It is compatible with and was tested with 
[php-oauth](https://github.com/fkooman/php-oauth).

# License
Licensed under the Apache License, Version 2.0;

   http://www.apache.org/licenses/LICENSE-2.0

# API
Using the library is straightforward:

    <?php
    require_once 'extlib/php-lib-remote-rs/lib/OAuth/RemoteResourceServer.php';

    use \OAuth\RemoteResourceServer as RemoteResourceServer;

    $config = array(
        "introspectionEndpoint" => "http://localhost/php-oauth/tokeninfo.php",
        "realm" => "My Demo Resource Server"
    );

    $rs = new RemoteResourceServer($config);
    $rs->verifyRequest();

Only the `introspectionEndpoint` configuration parameter needs to be set.

* `introspectionEndpoint` (REQUIRED) specify the location at which to verify 
  the OAuth token;
* `realm` (OPTIONAL) specify the "realm" of the RS that is used when 
  returning errors to the client using the `WWW-Authenticate` header. Default 
  value is `Resource Server`;

## Verify Tokens
If you write a simple piece of software that does not use any framework for 
handling HTTP requests and responses you can use the following method to handle
all communication with the client by itself:

    verifyRequest()
    
This will extract the Bearer Authorization header or `access_token` query 
parameter, verify it at the introspection endpoint and inform the client about
any problems.

If you use a HTTP framework some other methods are available to help you verfiy
tokens:

    verifyAuthorizationHeader($authorizationHeader)
    verifyQueryParameter(array $queryParameters)
    
The `verifyAuthorizationHeader` method checks the `Authorization` header 
provided.

The `verifyQueryParameter` method checks the query parameters provided.

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