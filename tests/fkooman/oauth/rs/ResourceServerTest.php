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

class ResourceServerTest extends \PHPUnit_Framework_TestCase
{
    public function testValidResponse()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(200, null, '{"active": true}'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $this->assertInstanceOf("\\fkooman\\oauth\\rs\\TokenIntrospection", $rs->verifyRequest("Bearer 001"));
    }

    public function testValidResponseSettingAuthorizationHeader()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(200, null, '{"active": true}'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->setAuthorizationHeader("Bearer 001");
        $this->assertInstanceOf("\\fkooman\\oauth\\rs\\TokenIntrospection", $rs->verifyToken());
    }

    public function testValidResponseSettingQueryParameter()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(200, null, '{"active": true}'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->setAccessTokenQueryParameter("001");
        $this->assertInstanceOf("\\fkooman\\oauth\\rs\\TokenIntrospection", $rs->verifyToken());
    }

    /**
     * @expectedException \fkooman\oauth\rs\ResourceServerException
     * @expectedExceptionMessage internal_server_error
     */
    public function testNoJsonResponse()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(200, null, 'BROKEN'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->verifyRequest("Bearer 001");
    }

    /**
     * @expectedException \fkooman\oauth\rs\ResourceServerException
     * @expectedExceptionMessage internal_server_error
     */
    public function testNoJsonArrayResponse()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(200, null, 'true'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->verifyRequest("Bearer 001");
    }

    /**
     * @expectedException \fkooman\oauth\rs\ResourceServerException
     * @expectedExceptionMessage internal_server_error
     */
    public function testErrorResponseCode()
    {
        $plugin = new \Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new \Guzzle\Http\Message\Response(404, null, 'Not Found'));
        $client = new \Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $rs->verifyRequest("Bearer 001");
    }

    /**
     * @expectedException \fkooman\oauth\rs\ResourceServerException
     * @expectedExceptionMessage invalid_request
     */
    public function testMultipleTokenMethods()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $introspection = $rs->verifyRequest("Bearer 003", "003");
    }

    /**
     * @expectedException \fkooman\oauth\rs\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testNoTokenMethods()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $introspection = $rs->verifyRequest();
    }

    /**
     * @expectedException \fkooman\oauth\rs\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testNotBearerAuthorizationHeader()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $introspection = $rs->verifyRequest("Basic Zm9vOmJhcg==");
    }

    /**
     * @expectedException \fkooman\oauth\rs\ResourceServerException
     * @expectedExceptionMessage invalid_token
     */
    public function testInvalidTokenCharacters()
    {
        $rs = new ResourceServer(new \Guzzle\Http\Client());
        $introspection = $rs->verifyRequest(null, ",./'_=09211#4$");
    }
}
