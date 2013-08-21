[![Build Status](https://www.travis-ci.org/fkooman/php-oauth-lib-rs.png?branch=master)](https://www.travis-ci.org/fkooman/php-oauth-lib-rs)

# Introduction
This is a library to implement an OAuth 2.0 resource server (RS). The library
can be used by any service that wants to accept OAuth 2.0 bearer tokens.

It is compatible with and was tested with 
[php-oauth](https://github.com/fkooman/php-oauth).

The library uses the "introspection" endpoint of the OAuth AS to verify the 
access tokens it receives from a client. This is explained in the specification
`draft-richer-oauth-introspection-04.txt`, included in the `docs` directory.

# License
Licensed under the Apache License, Version 2.0;

   http://www.apache.org/licenses/LICENSE-2.0

# API
Using the library is straightforward, you can install it in your project using
[Composer](http://www.getcomposer.org) and add this library to your `requires`
in `composer.json`:

    $ php composer.phar require fkooman/php-oauth-lib-rs dev-master

Or of course any of the released versions by tag.

To use the API:

    $rs = new ResourceServer(new Client("http://localhost/oauth/php-oauth/introspect.php"));

Now you have to somehow get the `Authorization` header value and/or the `GET` 
query parameters, see example below on how to do that.

    verifyRequest($authorizationHeader, $accessTokenQueryParameter)

The `$authorizationHeader` would be of the form `Bearer xyz`, and the 
`$accessTokenQueryParameter` would just be `xyz`. The value of the parameter to
`verifyRequest` can be `null` which means that particular option is not used. 
They can however not both be `null`, and also not both be set!

The `verifyRequest` method returns a `TokenIntrospection` object with a number
of methods:

    public function getActive()
    public function getExpiresAt()
    public function getIssuedAt()
    public function getScope()
    public function getClientId()
    public function getSub()
    public function getAud()
    public function getTokenType()

If you read the specification they will make sense. In addition there is one 
extra call `getToken()` that returns the complete response from the 
introspection endpoint. This way you can also access proprietary fields.

You **MUST** always first check whether the token was considered active using
`getActive()` before using any of the other methods. Using the other methods on
a non-active token will return `false`.

## Exceptions
The library will return exceptions when using the `verifyRequest` method, you
can catch these exceptions and send the appropriate response to the client
using your own (HTTP) framework.

The exception provides some helper methods to help with constructing a response
for the client:

    public function getDescription()
    public function setRealm($resourceServerRealm)
    public function getRealm()
    public function getStatusCode()
    public function getAuthenticateHeader()
    public function getBody()

The `getStatusCode()` method will get you the (integer) HTTP response code
to send to the client. The method `setRealm($resourceServerRealm)` allows you 
to set the "realm" that will be part of the `WWW-Authenticate` header you can
retrieve with the `getAuthenticateHeader()` method. The `getBody()` method 
gives you a JSON encoded response body you can send back to the client, this is 
OPTIONAL.

# Example
This is a full example using this library.

    <?php
    require_once 'vendor/autoload.php';

    use fkooman\oauth\rs\ResourceServer;
    use fkooman\oauth\rs\ResourceServerException;
    use Guzzle\Http\Client;

    try {
        // initialize the Resource Server, point it to introspection endpoint
        $rs = new ResourceServer(new Client("http://localhost/oauth/php-oauth/introspect.php"));

        // get the Authorization header (if provided, through ugly Apache function)
        $requestHeaders = apache_request_headers();
        $authorizationHeader = isset($requestHeaders['Authorization']) ? $requestHeaders['Authorization'] : null;

        // get the query parameter (if provided)
        $accessTokenQueryParameter = isset($_GET['access_token']) ? $_GET['access_token'] : null;

        // now verify the Authorization header and/or query parameter
        $introspection = $rs->verifyRequest($authorizationHeader, $accessTokenQueryParameter);

        // check if the token is active
        if ($introspection->getActive()) {
            // check we have the required scope 'foo'
            // NOTE: only getActive is required to be available, any of the other
            // introspection method objects can return "false" when not provided
            // by the introspection endpoint
            $scope = explode(" ", $introspection->getScope());
            if (!in_array("foo", $scope)) {
                throw new ResourceServerException("insufficient_scope", "scope 'foo' required");
            }
            $output = array("user_id" => $introspection->getSub());
        } else {
            $output = array("active" => false);
        }

        header("Content-Type: application/json");
        echo json_encode($output);
    } catch (ResourceServerException $e) {
        $e->setRealm("Foo");
        header("HTTP/1.1 " . $e->getStatusCode());
        if (null !== $e->getAuthenticateHeader()) {
            // for "internal_server_error" responses no WWW-Authenticate header is set
            header("WWW-Authenticate: " . $e->getAuthenticateHeader());
        }
        header("Content-Type: application/json");
        $output = array(
                "error" => $e->getMessage(),
                "code" => $e->getStatusCode(),
                "error_description" => $e->getDescription()
            )
        );
        echo json_encode($output);
    } catch (Exception $e) {
        // handle generic exceptions
        header("Content-Type: application/json");
        echo json_encode($e->getMessage());
    }

In "real" applications you want to be more resilient on how to obtain the 
`Authorization` header. For example, using the Apache specific example as shown
above is not really nice. Because PHP removes the `Authorization` header by 
assuming it will always be `Basic` authentication it is not available in the 
`$_SERVER` array. If you want to make it available there you can use the 
following Apache configuration snippet:

    RewriteEngine On
    RewriteCond %{HTTP:Authorization} ^(.+)$
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]

That will make `HTTP_AUTHORIZATION` available in `$_SERVER`. If you use some
framework it may already take care of this for you.
