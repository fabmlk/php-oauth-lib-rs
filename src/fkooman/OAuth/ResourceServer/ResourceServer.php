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

/**
 * Class ResourceServer.
 */
class ResourceServer
{
    /* @var \GuzzleHttp\Client */
    private $httpClient;

    /* @var string|null */
    private $authorizationHeader;

    /* @var string|null */
    private $accessTokenQueryParameter;

    /**
     * @param \GuzzleHttp\Client $httpClient
     *                           the client pointing to the introspection endpoint
     */
    public function __construct(\GuzzleHttp\Client $httpClient)
    {
        $this->httpClient = $httpClient;
    }

    /**
     * @param $authorizationHeader
     */
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

    /**
     * @param $accessTokenQueryParameter
     */
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

    /**
     * @param \Closure      $introspectionRequestFactory
     * @param \Closure|null $tokenIntrospectionFactory
     * @return DefaultTokenIntrospection|mixed
     *
     * @throws ResourceServerException
     */
    public function verifyToken(\Closure $introspectionRequestFactory, \Closure $tokenIntrospectionFactory = null)
    {
        // one type should at least be set
        if (null === $this->authorizationHeader && null === $this->accessTokenQueryParameter) {
            throw new ResourceServerException("no_token", "missing token");
        }
        // but not both
        if (null !== $this->authorizationHeader && null !== $this->accessTokenQueryParameter) {
            throw new ResourceServerException("invalid_request", "more than one method for including an access token used");
        }
        if (null !== $this->authorizationHeader) {
            $bearerToken = $this->authorizationHeader;
        } else {
            $bearerToken = $this->accessTokenQueryParameter;
        }

        $this->validateTokenSyntax($bearerToken);

        $request = $introspectionRequestFactory($bearerToken);
        if (!$request instanceof \Psr\Http\Message\RequestInterface) {
            throw new \UnexpectedValueException(
                sprintf('Introspection request expected to be an instance of %s', \Psr\Http\Message\RequestInterface::class)
            );
        }

        try {
            $response = $this->httpClient->send($request);
            $responseData = json_decode($response->getBody(), true);

            if (!is_array($responseData)) {
                throw new ResourceServerException("internal_server_error", "malformed response data from introspection endpoint");
            }

            $tokenIntrospection = $tokenIntrospectionFactory ? $tokenIntrospectionFactory($responseData) : new DefaultTokenIntrospection($responseData);
            if (!$tokenIntrospection instanceof AbstractTokenIntrospection) {
                throw new \UnexpectedValueException(sprintf('Token introspection expected to be an instance of %s', AbstractTokenIntrospection::class));
            }

            // check if the token was active
            if (!$tokenIntrospection->isActive()) {
                throw new ResourceServerException("invalid_token", "the access token is not active");
            }
            // check if it was not expired
            if ($tokenIntrospection->getExpiresAt() && $tokenIntrospection->isExpired()) {
                throw new ResourceServerException("invalid_token", "the access token expired");
            }

            return $tokenIntrospection;
        } catch (\GuzzleHttp\Exception\GuzzleException $e) {
            // error when contacting endpoint, or no JSON data returned
            throw new ResourceServerException("internal_server_error", "unable to contact introspection endpoint or malformed response data", $e->getCode(), $e);
        } catch (TokenIntrospectionException $e) {
            // may be thrown by an instance of AbstractTokenIntrospection
            throw new ResourceServerException("invalid_token", $e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Resolve profile data from a psr7 request.
     * As there is no standard for response structure, the guzzle response is returned as is, without further parsing.
     *
     * @param \Psr\Http\Message\RequestInterface $profileRequest
     * @return array|mixed|null|\Psr\Http\Message\ResponseInterface
     *
     * @throws ResourceServerException
     */
    public function resolveProfile(\Psr\Http\Message\RequestInterface $profileRequest)
    {
        try {
            $response = $this->httpClient->send($profileRequest);
        } catch (\GuzzleHttp\Exception\GuzzleException $e) {
            throw new ResourceServerException("internal_server_error", "unable to contact profile endpoint", $e->getCode(), $e);
        }

        return $response;
    }

    /**
     * @param $token
     *
     * @throws ResourceServerException
     */
    private function validateTokenSyntax($token)
    {
        // b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
        if (1 !== preg_match('|^[[:alpha:][:digit:]-._~+/]+=*$|', $token)) {
            throw new ResourceServerException("invalid_token", "the access token is not a valid b64token");
        }
    }
}
