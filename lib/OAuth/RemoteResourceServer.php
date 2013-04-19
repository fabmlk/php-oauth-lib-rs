<?php

/**
 *  Copyright 2013 François Kooman <fkooman@tuxed.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace OAuth;

class RemoteResourceServer
{
    private $_config;

    private $_grantedScope;
    private $_resourceOwnerId;
    private $_resourceOwnerAttributes;
    private $_isVerified;

    public function __construct(array $c)
    {
        $this->_config = $c;

        $this->_resourceOwnerId = NULL;
        $this->_grantedScope = NULL;
        $this->_resourceOwnerAttributes = NULL;
        $this->_isVerified = FALSE;
    }

    /**
     * Verify the Authorization Bearer token.
     *
     * Note: this only works on Apache as the PHP function
     * "apache_request_headers" is used. On other web servers, or when using
     * a framework, please use the verifyAuthorizationHeader function instead
     * where you can directly specify the contents of the Authorization header.
     */
    public function verifyRequest()
    {
        try {
            // FIXME: check if the function apache_request_headers exists!
            // FIXME: check $_SERVER['X-AUTHORIZATION'] as well
            $apacheHeaders = apache_request_headers();
            $headerKeys = array_keys($apacheHeaders);
            $keyPositionInArray = array_search(strtolower("Authorization"), array_map('strtolower', $headerKeys));
            $authorizationHeader = (FALSE !== $keyPositionInArray) ? $apacheHeaders[$headerKeys[$keyPositionInArray]] : NULL;
            // FIXME: function below does not exist anymore!
            if (NULL !== $authorizationHeader) {
                return $this->verifyAuthorizationHeader($authorizationHeader);
            }
            if (is_array($_GET) && isset($_GET['access_token'])) {
                return $this->verifyQueryParameter($_GET);
            }
            throw new RemoteResourceServerException("no_token","no bearer token provided");

        } catch (RemoteResourceServerException $e) {
            // send response directly to client, halt execution of calling script as well
            $e->setRealm($this->_getRequiredConfigParameter("realm"));
            header("HTTP/1.1 " . $e->getResponseCode());
            header("WWW-Authenticate: " . $e->getAuthenticateHeader());
            header("Content-Type: application/json");
            die($e->getContent());
        }
    }

    /**
     * Verify the Authorization Bearer token.
     *
     * @param $authorizationHeader The actual content of the Authorization
     * header, e.g.: "Bearer abcdef"
     */
    public function verifyAuthorizationHeader($authorizationHeader)
    {
        if (0 !== strpos($authorizationHeader, "Bearer ")) {
            throw new RemoteResourceServerException("invalid_request", "no bearer token type in authorization header");
        }
        $token = substr($authorizationHeader, 7);

        return $this->_verifyBearerToken($token);
    }

    public function verifyQueryParameter(array $queryParameters)
    {
        $token = isset($queryParameters['access_token']) ? $queryParameters['access_token'] : NULL;
        if (NULL === $token) {
            throw new RemoteResourceServerException("invalid_request", "no bearer token in query parameters");
        }

        return $this->_verifyBearerToken($token);
    }

    private function _verifyBearerToken($token)
    {
        // b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
        if ( 1 !== preg_match('|^[[:alpha:][:digit:]-._~+/]+=*$|', $token)) {
            throw new RemoteResourceServerException("invalid_token", "the access token is not a valid b64token");
        }

        $introspectionEndpoint = $this->_getRequiredConfigParameter("introspectionEndpoint");
        $get = array("token" => $token);

        $curlChannel = curl_init();

        if (0 !== strpos($introspectionEndpoint, "file://")) {
            $separator = (FALSE === strpos($introspectionEndpoint, "?")) ? "?" : "&";
            $introspectionEndpoint .= $separator . http_build_query($get);
        } else {
            // file cannot have query parameter, use accesstoken as JSON file instead
            $introspectionEndpoint .= $token . ".json";
        }
        curl_setopt_array($curlChannel, array (
            CURLOPT_URL => $introspectionEndpoint,
            //CURLOPT_FOLLOWLOCATION => 1,
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_SSL_VERIFYPEER => 1,
            CURLOPT_SSL_VERIFYHOST => 2,
        ));

        $output = curl_exec($curlChannel);

        if (FALSE === $output) {
            $error = curl_error($curlChannel);
            throw new RemoteResourceServerException("internal_server_error", "unable to contact introspection endpoint (" . $error . ")");
        }

        $httpCode = curl_getinfo($curlChannel, CURLINFO_HTTP_CODE);
        curl_close($curlChannel);

        if (0 !== strpos($introspectionEndpoint, "file://")) {
            // not a file
            if (200 !== $httpCode) {
                throw new RemoteResourceServerException("internal_server_error", "malformed request to introspection endpoint");
            }
        }

        $data = json_decode($output, TRUE);
        $jsonError = json_last_error();
        if (JSON_ERROR_NONE !== $jsonError) {
            throw new RemoteResourceServerException("internal_server_error", "unable to decode response from introspection endpoint");
        }
        if (!is_array($data) || !isset($data['active']) || !is_bool($data['active'])) {
            throw new RemoteResourceServerException("internal_server_error", "malformed response from introspection endpoint");
        }
        if (!$data['active']) {
            throw new RemoteResourceServerException("invalid_token", "the token is not active");
        }

        return new TokenIntrospection($data);
    }

    private function _getRequiredConfigParameter($key)
    {
        if (!array_key_exists($key, $this->_config)) {
            throw new RemoteResourceServerException("internal_server_error", "missing configuration parameter (" . $key . ")");
        }

        return $this->_config[$key];
    }
}

class TokenIntrospection
{
    private $_response;

    public function __construct(array $response)
    {
        if (!isset($response['active']) || !is_bool($response['active'])) {
            throw new RemoteResourceServerException("internal_server_error", "malformed response from introspection endpoint");
        }
        $this->_response = $response;
    }

    /**
     * REQUIRED.  Boolean indicator of whether or not the presented
     * token is currently active.
     */
    public function getActive()
    {
        return $this->_response['active'];
    }

    /**
     * OPTIONAL.  Integer timestamp, measured in the number of
     * seconds since January 1 1970 UTC, indicating when this token will
     * expire.
     */
    public function getExpiresAt()
    {
        return $this->_getKeyValue('expires_at');
    }

    /**
     * OPTIONAL.  Integer timestamp, measured in the number of
     * seconds since January 1 1970 UTC, indicating when this token was
     * originally issued.
     */
    public function getIssuedAt()
    {
        return $this->_getKeyValue('issued_at');
    }

    /**
     * OPTIONAL.  A space-separated list of strings representing the
     * scopes associated with this token, in the format described in
     * Section 3.3 of OAuth 2.0 [RFC6749].
     */
    public function getScope()
    {
        return $this->_getKeyValue('scope');
    }

    /**
     * OPTIONAL.  Client Identifier for the OAuth Client that
     * requested this token.
     */
    public function getClientId()
    {
        return $this->_getKeyValue('client_id');
    }

    /**
     * OPTIONAL.  Local identifier of the Resource Owner who authorized
     * this token.
     */
    public function getSub()
    {
        return $this->_getKeyValue('sub');
    }

    /**
     * OPTIONAL.  Service-specific string identifier or list of string
     * identifiers representing the intended audience for this token.
     */
    public function getAud()
    {
        return $this->_getKeyValue('aud');
    }

    private function _getKeyValue($key)
    {
        return isset($this->_response[$key]) ? $this->_response[$key] : FALSE;
    }

    /* ADDITIONAL HELPER METHODS */

    public function getResourceOwnerId()
    {
        return $this->getSub();
    }

    public function getScopeAsArray()
    {
        if (FALSE === $this->getScope()) {
            return array();
        } else {
            return explode(" ", $this->getScope());
        }
    }

    public function hasScope($scope)
    {
        if (FALSE === $this->getScopeAsArray()) {
            return FALSE;
        }

        return in_array($scope, $this->getScopeAsArray());
    }

    public function requireScope($scope)
    {
        if (FALSE === $this->hasScope($scope)) {
            throw new RemoteResourceServerException("insufficient_scope", "no permission for this call with granted scope");
        }
    }

    /**
     * At least one of the scopes should be granted.
     *
     * @param  array $scope the list of scopes of which one should be granted
     * @return TRUE  when at least one of the requested scopes was granted,
     *         FALSE when none were granted.
     */
    public function hasAnyScope(array $scope)
    {
        foreach ($scope as $s) {
            if (in_array($s, $this->hasScope())) {
                return TRUE;
            }
        }

        return FALSE;
    }

    /* PROPRIETARY EXTENSION "X-ENTITLEMENT" */
    public function getEntitlement()
    {
        return $this->_getKeyValue('x-entitlement');
    }

    public function getEntitlementAsArray()
    {
        if (FALSE === $this->getEntitlement()) {
            return array();
        } else {
            return explode(" ", $this->getEntitlement());
        }
    }

    public function hasEntitlement($entitlement)
    {
        if (FALSE === $this->getEntitlementAsArray()) {
            return FALSE;
        }

        return in_array($entitlement, $this->getEntitlementAsArray());
    }

    public function requireEntitlement($scope)
    {
        if (FALSE === $this->hasEntitlement($scope)) {
            throw new RemoteResourceServerException("insufficient_scope", "no permission for this call with granted entitlement");
        }
    }
}

class RemoteResourceServerException extends \Exception
{
    private $description;
    private $responseCode;
    private $realm;

    public function __construct($message, $description, $code = 0, Exception $previous = null)
    {
       switch ($message) {
            case "no_token":
            case "invalid_token":
                $this->responseCode = 401;
                break;
            case "insufficient_scope":
            case "insufficient_entitlement":
                $this->responseCode = 403;
                break;
            case "internal_server_error":
                $this->responseCode = 500;
                break;
            case "invalid_request":
            default:
                $this->responseCode = 400;
                break;
        }

        $this->description = $description;
        $this->realm = "Resource Server";

        parent::__construct($message, $code, $previous);
    }

    public function getDescription()
    {
        return $this->description;
    }

    public function setRealm($resourceServerRealm)
    {
        $this->realm = (is_string($resourceServerRealm) && !empty($resourceServerRealm)) ? $resourceServerRealm : "Resource Server";
    }

    public function getResponseCode()
    {
        return $this->responseCode;
    }

    public function getAuthenticateHeader()
    {
        $authenticateHeader = NULL;
        if (500 !== $this->responseCode) {
            if ("no_token" === $this->message) {
                // no authorization header is a special case, the client did not know
                // authentication was required, so tell it now without giving error message
                $authenticateHeader = sprintf('Bearer realm="%s"', $this->realm);
            } else {
                $authenticateHeader = sprintf('Bearer realm="%s",error="%s",error_description="%s"', $this->realm, $this->message, $this->description);
            }
        }

        return $authenticateHeader;
    }

    public function getContent()
    {
        return json_encode(array("error" => $this->message, "error_description" => $this->description));
    }

}
