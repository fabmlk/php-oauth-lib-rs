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

namespace fkooman\oauth\rs;

class ResourceServer
{
    private $httpClient;

    /**
     * @param \Guzzle\Http\Client $httpClient
     *          the client pointing to the introspection endpoint
     */
    public function __construct(\Guzzle\Http\Client $httpClient)
    {
        $this->httpClient = $httpClient;
    }

    /**
     * @param string authorizationHeader
     *     the value of the Authorzation header in the form: "Bearer xyz"
     * @param string accessTokenQueryParameter
     *     the value of the "access_token" query parameter in the form: "xyz"
     */
    public function verifyRequest($authorizationHeader = null, $accessTokenQueryParameter = null)
    {
        if (!empty($authorizationHeader) && !empty($accessTokenQueryParameter)) {
            // two tokens provided
            throw new ResourceServerException(
                "invalid_request",
                "more than one method for including an access token used"
            );
        }
        if (!empty($authorizationHeader)) {
            if (0 !== stripos($authorizationHeader, "Bearer ")) {
                throw new ResourceServerException("invalid_token", "not a bearer token");
            }

            return $this->verifyBearerToken(substr($authorizationHeader, 7));
        }
        if (!empty($accessTokenQueryParameter)) {
            return $this->verifyBearerToken($accessTokenQueryParameter);
        }
        throw new ResourceServerException("no_token", "missing token");
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

    public function verifyBearerToken($token)
    {
        $this->validateTokenSyntax($token);

        try {
            $request = $this->httpClient->get();
            $request->getQuery()->add("token", $token);
            $response = $request->send();

            $responseData = $response->json();
            if (!is_array($responseData)) {
                throw new ResourceServerException(
                    "internal_server_error",
                    "malformed response data from introspection endpoint"
                );
            }

            return new TokenIntrospection($responseData);
        } catch (\Guzzle\Common\Exception\RuntimeException $e) {
            // error when contacting endpoint, or no JSON data returned
            throw new ResourceServerException(
                "internal_server_error",
                "unable to contact introspection endpoint or malformed response data"
            );
        }
    }
}
