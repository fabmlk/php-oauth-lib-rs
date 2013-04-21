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
    require_once 'lib/OAuth/RemoteResourceServer.php';

    use \OAuth\RemoteResourceServer as RemoteResourceServer;

    $config = array(
        "introspectionEndpoint" => "http://localhost/php-oauth/introspect.php",
        "realm" => "My Demo Resource Server"
    );

    $rs = new RemoteResourceServer($config);
    $introspection = $rs->verifyAndHandleRequest();

    echo $introspection->getSub();  // resourceOwnerId

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

    verifyAndHandleRequest()
    
This will extract the Bearer Authorization header or `access_token` query 
parameter, verify it at the introspection endpoint and inform the client 
directly about any problems.

If you use a HTTP framework an other method is available to help you verify
tokens:

    verifyRequest(array $requestHeaders, array $queryParameters)
    
You can specify an array with request headers and an array with query 
parameters. You can just feed the library all request headers and query 
parameters as only the relevant `Authorization` and/or `access_token` 
query parameter are evaluated. If the client provides both an `Authorization` 
header and an `access_token` query parameter an error will be returned as it 
is not allowed to specify both methods simultaneously.

## Retrieve Resource Owner Information
After the `verifyRequest()`, or any of the other verify functions, some methods 
are available to retrieve information about the resource owner and client 
assuming the verification was successful.

* `getResourceOwnerId()` (the unique resource owner identifier)
* `getScope()` (the scope granted to the client accessing this resource)
* `getEntitlement()` (the entitlement the resource owner has when accessing this 
  resource)

Note that the `getEntitlement()` methods is not supported by all authorization 
servers and is a properietary extension to 
[https://github.com/fkooman/php-oauth](php-oauth).

## Exceptions
The library will return exceptions when using the `verifyRequest` method, you
can catch these exceptions and send the appropriate response to the client
using your own (HTTP) framework.

The exception provides some helper methods to help with constructing a response
for the client:

* `getResponseCode()`
* `getAuthenticateHeader()`
* `setRealm($realm)`
* `getContent()`

The `getResponseCode()` method will get you the (integer) HTTP response code
to send to the client. The method `setRealm($realm)` allows you to set the 
"realm" that will be part of the `WWW-Authenticate` header you can retrieve
with the `getAuthenticateHeader()` method. The `getContent()` method gives you
a `JSON` formatted response you can send back to the client, this is OPTIONAL.

Here is an example on how to use this library with your own exception handling:

    <?php
    require_once 'lib/OAuth/RemoteResourceServer.php';

    use \OAuth\RemoteResourceServer as RemoteResourceServer;
    use \OAuth\RemoteResourceServerException as RemoteResourceServerException;

    $config = array(
        "introspectionEndpoint" => "http://localhost/php-oauth/introspect.php",
    );

    try {
        $rs = new RemoteResourceServer($config);
        $introspection = $rs->verifyRequest(apache_request_headers(), $_GET);
        echo $introspection->getSub();
    } catch (RemoteResourceServerException $e) {
        $e->setRealm("Foo");
        header("HTTP/1.1 " . $e->getResponseCode());
        header("WWW-Authenticate: " . $e->getAuthenticateHeader());
        header("Content-Type: application/json");
        die($e->getContent());
    }