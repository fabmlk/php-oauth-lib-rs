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

class DefaultTokenIntrospection extends AbstractTokenIntrospection
{
    public function checkActive()
    {
        if (!is_bool($this->getActive())) {
            throw new TokenIntrospectionException("active key should be set and its value a boolean");
        }
    }

    public function checkExpiresAt()
    {
        $exp = $this->getExpiresAt();

        if ($exp && (!is_int($exp) || 0 > $exp)) {
            throw new TokenIntrospectionException("exp value must be positive integer");
        }

        // check whether token did not expire before it was issued
        if ($exp && $this->getIssuedAt() && $exp < $this->getIssuedAt()) {
            throw new TokenIntrospectionException("token expired before it was issued");
        }
    }

    public function checkIssuedAt()
    {
        $iat = $this->getIssuedAt();

        if ($iat && (!is_int($iat) || 0 > $iat)) {
            throw new TokenIntrospectionException("iat value must be positive integer");
        }

        // check whether token was not issued in the future
        if ($iat && time() < $iat) {
            throw new TokenIntrospectionException("token issued in the future");
        }
    }

    public function checkScope()
    {
        // check whether provided scope is an array
        if (isset($this->response['scope']) && !is_string($this->response['scope'])) {
            throw new TokenIntrospectionException("scope must be string");
        }
    }

    public function isActive()
    {
        return $this->getActive();
    }

    public function isExpired()
    {
        return time() > $this->getExpiresAt();
    }
}
