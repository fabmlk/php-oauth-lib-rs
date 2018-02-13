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

class ResourceServerTest extends \PHPUnit\Framework\TestCase
{
    private function createIntrospectionRequestFactory()
    {
        return function ($token) {
            $request = new \GuzzleHttp\Psr7\Request('POST', '/introspect');

            return $request->withBody(\GuzzleHttp\Psr7\stream_for(http_build_query([ 'access_token' => $token])));
        };
    }

    public function testValidToken()
    {
        $mock = new \GuzzleHttp\Handler\MockHandler([new \GuzzleHttp\Psr7\Response(200, [], '{"active": true}')]);
        $client = new \GuzzleHttp\Client(['base_uri' => "https://auth.example.org", 'handler' => \GuzzleHttp\HandlerStack::create($mock)]);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $this->assertInstanceOf("fkooman\\OAuth\\ResourceServer\\AbstractTokenIntrospection", $rs->verifyToken($this->createIntrospectionRequestFactory()));
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage invalid_token
     */
    public function testNonActiveToken()
    {
        $mock = new \GuzzleHttp\Handler\MockHandler([new \GuzzleHttp\Psr7\Response(200, [], '{"active": false}')]);
        $client = new \GuzzleHttp\Client(['base_uri' => "https://auth.example.org", 'handler' => \GuzzleHttp\HandlerStack::create($mock)]);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    public function testNonExpiredToken()
    {
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(200, [], sprintf('{"active": true, "exp": %d}', time() + 3600))
        ]);
        $client = new \GuzzleHttp\Client(['base_uri' => "https://auth.example.org", 'handler' => \GuzzleHttp\HandlerStack::create($mock)]);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $this->assertInstanceOf("fkooman\\OAuth\\ResourceServer\\AbstractTokenIntrospection", $rs->verifyToken($this->createIntrospectionRequestFactory()));
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage invalid_token
     */
    public function testExpiredToken()
    {
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(200, [], sprintf('{"active": true, "exp": %d}', time() - 3600))
        ]);
        $client = new \GuzzleHttp\Client(['base_uri' => "https://auth.example.org", 'handler' => \GuzzleHttp\HandlerStack::create($mock)]);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    public function testValidResponseSettingQueryParameter()
    {
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(200, [], '{"active": true}')
        ]);
        $client = new \GuzzleHttp\Client(['base_uri' => "https://auth.example.org", 'handler' => \GuzzleHttp\HandlerStack::create($mock)]);
        $rs = new ResourceServer($client);
        $rs->setAccessTokenQueryParameter("001");
        $this->assertInstanceOf("fkooman\\OAuth\\ResourceServer\\AbstractTokenIntrospection", $rs->verifyToken($this->createIntrospectionRequestFactory()));
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage internal_server_error
     */
    public function testNoJsonResponse()
    {
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(200, [], 'BROKEN')
        ]);
        $client = new \GuzzleHttp\Client(['base_uri' => "https://auth.example.org", 'handler' => \GuzzleHttp\HandlerStack::create($mock)]);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage internal_server_error
     */
    public function testNoJsonArrayResponse()
    {
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(200, [], 'true')
        ]);
        $client = new \GuzzleHttp\Client(['base_uri' => "https://auth.example.org", 'handler' => \GuzzleHttp\HandlerStack::create($mock)]);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage internal_server_error
     */
    public function testErrorResponseCode()
    {
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(404, [], 'Not Found')
        ]);
        $client = new \GuzzleHttp\Client(['base_uri' => "https://auth.example.org", 'handler' => \GuzzleHttp\HandlerStack::create($mock)]);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage invalid_request
     */
    public function testMultipleTokenMethods()
    {
        $rs = new ResourceServer(new \GuzzleHttp\Client());
        $rs->setAuthorizationHeader("Bearer 003");
        $rs->setAccessTokenQueryParameter("003");
        $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testNoTokenMethods()
    {
        $rs = new ResourceServer(new \GuzzleHttp\Client());
        $introspection = $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testNotBearerAuthorizationHeader()
    {
        $rs = new ResourceServer(new \GuzzleHttp\Client());
        $rs->setAuthorizationHeader("Basic Zm9vOmJhcg==");
        $introspection = $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testWrongAuthorizationHeader()
    {
        $rs = new ResourceServer(new \GuzzleHttp\Client());
        $rs->setAuthorizationHeader("Foo");
        $introspection = $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testNoStringAuthorizationHeader()
    {
        $rs = new ResourceServer(new \GuzzleHttp\Client());
        $rs->setAuthorizationHeader(456);
        $introspection = $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testEmptyStringAuthorizationHeader()
    {
        $rs = new ResourceServer(new \GuzzleHttp\Client());
        $rs->setAuthorizationHeader("Bearer ");
        $introspection = $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testEmptyStringAccessTokenQueryParameter()
    {
        $rs = new ResourceServer(new \GuzzleHttp\Client());
        $rs->setAccessTokenQueryParameter("");
        $introspection = $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testNoStringAccessTokenQueryParameter()
    {
        $rs = new ResourceServer(new \GuzzleHttp\Client());
        $rs->setAccessTokenQueryParameter(123);
        $introspection = $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage invalid_token
     */
    public function testInvalidTokenCharacters()
    {
        $rs = new ResourceServer(new \GuzzleHttp\Client());
        $rs->setAccessTokenQueryParameter(",./'_=09211#4$");
        $introspection = $rs->verifyToken($this->createIntrospectionRequestFactory());
    }

    public function testScopeResponse()
    {
        $mock = new \GuzzleHttp\Handler\MockHandler([
            new \GuzzleHttp\Psr7\Response(200, [], '{"active": true, "scope": "foo:rw bar:r"}')
        ]);
        $client = new \GuzzleHttp\Client(['base_uri' => "https://auth.example.org", 'handler' => \GuzzleHttp\HandlerStack::create($mock)]);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $v =  $rs->verifyToken($this->createIntrospectionRequestFactory());
        $this->assertInstanceOf("fkooman\\OAuth\\ResourceServer\\AbstractTokenIntrospection", $v);
    }
}
