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

use fkooman\OAuth\Common\Scope;

class TokenIntrospection
{
    private $response;

    public function __construct(array $response)
    {
        if (!isset($response['active']) || !is_bool($response['active'])) {
            throw new TokenIntrospectionException("active key should be set and its value a boolean");
        }

        if (isset($response['exp']) && (!is_int($response['exp']) || 0 > $response['exp'])) {
            throw new TokenIntrospectionException("exp value must be positive integer");
        }

        if (isset($response['iat']) && (!is_int($response['iat']) || 0 > $response['iat'])) {
            throw new TokenIntrospectionException("iat value must be positive integer");
        }

        // check whether token was not issued in the future
        if (isset($response['iat'])) {
            if (time() < $response['iat']) {
                throw new TokenIntrospectionException("token issued in the future");
            }
        }

        // check whether token did not expire before it was issued
        if (isset($response['exp']) && isset($response['iat'])) {
            if ($response['exp'] < $response['iat']) {
                throw new TokenIntrospectionException("token expired before it was issued");
            }
        }

        // check whether provided scope is an array
        if (isset($response['scope']) && !is_string($response['scope'])) {
                throw new TokenIntrospectionException("scope must be string");
        }

        $this->response = $response;
    }

    /**
     * REQUIRED.  Boolean indicator of whether or not the presented
     * token is currently active.
     */
    public function getActive()
    {
        return $this->response['active'];
    }

    /**
     * OPTIONAL.  Integer timestamp, measured in the number of
     * seconds since January 1 1970 UTC, indicating when this token will
     * expire.
     */
    public function getExpiresAt()
    {
        return $this->getKeyValue('exp');
    }

    /**
     * OPTIONAL.  Integer timestamp, measured in the number of
     * seconds since January 1 1970 UTC, indicating when this token was
     * originally issued.
     */
    public function getIssuedAt()
    {
        return $this->getKeyValue('iat');
    }

    /**
     * OPTIONAL.  A space-separated list of strings representing the
     * scopes associated with this token, in the format described in
     * Section 3.3 of OAuth 2.0 [RFC6749].
     *
     * @return fkooman\OAuth\Common\Scope
     */
    public function getScope()
    {
        $scopeValue = $this->getKeyValue('scope');
        if (false === $scopeValue) {
            return new Scope();
        }

        return Scope::fromString($scopeValue);
    }

    /**
     * OPTIONAL.  Client Identifier for the OAuth Client that
     * requested this token.
     */
    public function getClientId()
    {
        return $this->getKeyValue('client_id');
    }

    /**
     * OPTIONAL.  Local identifier of the Resource Owner who authorized
     * this token.
     */
    public function getSub()
    {
        return $this->getKeyValue('sub');
    }

    /**
     * OPTIONAL.  Service-specific string identifier or list of string
     * identifiers representing the intended audience for this token.
     */
    public function getAud()
    {
        return $this->getKeyValue('aud');
    }

    /**
     * OPTIONAL.  Type of the token as defined in OAuth 2.0
     * section 5.1.
     */
    public function getTokenType()
    {
        return $this->getKeyValue('token_type');
    }

    /**
     * Get the complete response from the introspection endpoint
     */
    public function getToken()
    {
        return $this->response;
    }

    private function getKeyValue($key)
    {
        if (!isset($this->response[$key])) {
            return false;
        }

        return $this->response[$key];
    }
}
