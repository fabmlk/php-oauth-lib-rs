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

namespace fkooman\OAuth\ResourceServer;

class ResourceServer
{
    /* @var \Guzzle\Http\Client */
    private $httpClient;

    /* @var string|null */
    private $authorizationHeader;

    /* @var string|null */
    private $accessTokenQueryParameter;

    /**
     * @param \Guzzle\Http\Client $httpClient
     *                                        the client pointing to the introspection endpoint
     */
    public function __construct(\Guzzle\Http\Client $httpClient)
    {
        $this->httpClient = $httpClient;
        $this->authorizationHeader = null;
        $this->accessTokenQueryParameter = null;
    }

    public function setAuthorizationHeader($authorizationHeader)
    {
        // must be string
        if (!is_string($authorizationHeader)) {
            return;
        }
        // string should have at least length 8
        if (7 >= strlen($authorizationHeader)) {
            return;
        }
        // string should start with "Bearer "
        if (0 !== stripos($authorizationHeader, "Bearer ")) {
            return;
        }
        $this->authorizationHeader = substr($authorizationHeader, 7);
    }

    public function setAccessTokenQueryParameter($accessTokenQueryParameter)
    {
        // must be string
        if (!is_string($accessTokenQueryParameter)) {
            return;
        }
        // string should have at least length 1
        if (0 >= strlen($accessTokenQueryParameter)) {
            return;
        }
        $this->accessTokenQueryParameter = $accessTokenQueryParameter;
    }

    public function verifyToken()
    {
        // one type should at least be set
        if (null === $this->authorizationHeader && null === $this->accessTokenQueryParameter) {
            throw new ResourceServerException("no_token", "missing token");
        }
        // but not both
        if (null !== $this->authorizationHeader && null !== $this->accessTokenQueryParameter) {
            throw new ResourceServerException(
                "invalid_request",
                "more than one method for including an access token used"
            );
        }
        if (null !== $this->authorizationHeader) {
            $bearerToken = $this->authorizationHeader;
        } else {
            $bearerToken = $this->accessTokenQueryParameter;
        }

        $this->validateTokenSyntax($bearerToken);

        try {
            $request = $this->httpClient->get();
            $request->getQuery()->add("token", $bearerToken);
            $response = $request->send();

            $responseData = $response->json();
            if (!is_array($responseData)) {
                throw new ResourceServerException(
                    "internal_server_error",
                    "malformed response data from introspection endpoint"
                );
            }

            $tokenIntrospection = new TokenIntrospection($responseData);

            // check if the token was active
            if (!$tokenIntrospection->getActive()) {
                throw new ResourceServerException("invalid_token", "the access token is not active");
            }
            // check if it was not expired
            if (false !== $tokenIntrospection->getExpiresAt()) {
                if (time() > $tokenIntrospection->getExpiresAt()) {
                    throw new ResourceServerException("invalid_token", "the access token expired");
                }
            }

            return $tokenIntrospection;
        } catch (\Guzzle\Common\Exception\RuntimeException $e) {
            // error when contacting endpoint, or no JSON data returned
            throw new ResourceServerException(
                "internal_server_error",
                "unable to contact introspection endpoint or malformed response data"
            );
        }
    }

    private function validateTokenSyntax($token)
    {
        // b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
        if (1 !== preg_match('|^[[:alpha:][:digit:]-._~+/]+=*$|', $token)) {
            throw new ResourceServerException(
                "invalid_token",
                "the access token is not a valid b64token"
            );
        }
    }
}
