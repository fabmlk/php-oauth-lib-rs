# Release History

## 0.7.0
* Switch to using fkooman/oauth-common for Scope handling
* Rename package to fkooman/oauth-rs

## 0.6.1
* ResourceServerException for using both setAuthorizationHeader() and 
  setAccessTokenQueryParameter() is now thrown in verifyToken() instead of in 
  the setters.

## 0.6.0
* Again, API change, ResourceServerException will be thrown if token is not
  active, or when it expired

## 0.5.0
* Again, API change, change namespace to fkooman\OAuth\ResourceServer from
  fkooman\oauth\as to be more in line with the other projects
* Always throw TokenIntrospectionException when token is not valid, i.e.:
  `{"active":false}`

## 0.4.0
* Again, API change, see README (first set AuthorizationHeader and/or 
  AccessTokenQueryString before calling verifyToken() instead of them being a 
  parameter of verifyRequest())
* Add phpunit.xml.dist (to set bootstrap info)

## 0.3.0
* Again, major API overhaul, see README
* Use Guzzle for HTTP requests to token introspection endpoint
* Finish unit tests (100% coverage)

## 0.2.0
* API overhaul, see README
* No longer support handling requests for the caller
* Update Exception to return array instead of JSON with getContent(), and call 
  it getResponseAsArray() now

## 0.1.1
* Update code to better match PSR-2 guidelines
* Update the included introspection draft

## 0.1.0
* Initial release
