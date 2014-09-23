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

class ResourceServerTest extends \PHPUnit_Framework_TestCase
{
    public function testValidToken()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(200, null, '{"active": true}'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $this->assertInstanceOf("fkooman\\OAuth\\ResourceServer\\TokenIntrospection", $rs->verifyToken());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage invalid_token
     */
    public function testNonActiveToken()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(200, null, '{"active": false}'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $rs->verifyToken();
    }

    public function testNonExpiredToken()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(
            new \Guzzle\Http\Message\Response(
                200,
                null,
                sprintf('{"active": true, "exp": %d}', time() + 3600)
            )
        );
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $this->assertInstanceOf("fkooman\\OAuth\\ResourceServer\\TokenIntrospection", $rs->verifyToken());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage invalid_token
     */
    public function testExpiredToken()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(
            new \Guzzle\Http\Message\Response(
                200,
                null,
                sprintf('{"active": true, "exp": %d}', time() - 3600)
            )
        );
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $rs->verifyToken();
    }

    public function testValidResponseSettingQueryParameter()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(200, null, '{"active": true}'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->setAccessTokenQueryParameter("001");
        $this->assertInstanceOf("fkooman\\OAuth\\ResourceServer\\TokenIntrospection", $rs->verifyToken());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage internal_server_error
     */
    public function testNoJsonResponse()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(200, null, 'BROKEN'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $rs->verifyToken();
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage internal_server_error
     */
    public function testNoJsonArrayResponse()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(200, null, 'true'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $rs->verifyToken();
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage internal_server_error
     */
    public function testErrorResponseCode()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(404, null, 'Not Found'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $rs->verifyToken();
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage invalid_request
     */
    public function testMultipleTokenMethods()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $rs->setAuthorizationHeader("Bearer 003");
        $rs->setAccessTokenQueryParameter("003");
        $rs->verifyToken();
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testNoTokenMethods()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $introspection = $rs->verifyToken();
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testNotBearerAuthorizationHeader()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $rs->setAuthorizationHeader("Basic Zm9vOmJhcg==");
        $introspection = $rs->verifyToken();
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testWrongAuthorizationHeader()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $rs->setAuthorizationHeader("Foo");
        $introspection = $rs->verifyToken();
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testNoStringAuthorizationHeader()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $rs->setAuthorizationHeader(456);
        $introspection = $rs->verifyToken();
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testEmptyStringAuthorizationHeader()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $rs->setAuthorizationHeader("Bearer ");
        $introspection = $rs->verifyToken();
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testEmptyStringAccessTokenQueryParameter()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $rs->setAccessTokenQueryParameter("");
        $introspection = $rs->verifyToken();
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testNoStringAccessTokenQueryParameter()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $rs->setAccessTokenQueryParameter(123);
        $introspection = $rs->verifyToken();
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\ResourceServerException
     * @expectedExceptionMessage invalid_token
     */
    public function testInvalidTokenCharacters()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $rs->setAccessTokenQueryParameter(",./'_=09211#4$");
        $introspection = $rs->verifyToken();
    }

    public function testScopeResponse()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(200, null, '{"active": true, "scope": "foo:rw bar:r"}'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $v = $rs->verifyToken();
        $this->assertInstanceOf("fkooman\\OAuth\\ResourceServer\\TokenIntrospection", $v);
    }
}
