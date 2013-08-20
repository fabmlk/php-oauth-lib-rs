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

class RemoteResourceServer
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
        if (empty($authorizationHeader) && empty($accessTokenQueryParameter)) {
            // no token
            throw new RemoteResourceServerException("no_token", "missing token");
        }

        if (!empty($authorizationHeader) && !empty($accessTokenQueryParameter)) {
            // two tokens provided
            throw new RemoteResourceServerException("invalid_request", "more than one method for including an access token used");
        }

        if (!empty($authorizationHeader)) {
            if (0 !== stripos($authorizationHeader, "Bearer ")) {
                throw new RemoteResourceServerException("invalid_token", "not a bearer token");
            }

            return $this->verifyBearerToken(substr($authorizationHeader, 7));
        }
        if (!empty($accessTokenQueryParameter)) {
            return $this->verifyBearerToken($accessTokenQueryParameter);
        }
    }

    private function validateTokenSyntax($token)
    {
        // b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
        if (1 !== preg_match('|^[[:alpha:][:digit:]-._~+/]+=*$|', $token)) {
            throw new RemoteResourceServerException("invalid_token", "the access token is not a valid b64token");
        }
    }

    public function verifyBearerToken($token)
    {
        $this->validateTokenSyntax($token);

        $request = $this->httpClient->get();
        $request->getQuery()->add("token", $token);
        $response = $request->send();

        return new TokenIntrospection($response->json());
    }
}
