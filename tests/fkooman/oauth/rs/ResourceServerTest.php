<?php

/**
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

require_once 'vendor/autoload.php';

use fkooman\oauth\rs\ResourceServer;
use fkooman\oauth\rs\ResourceServerException;

class ResourceServerTest extends PHPUnit_Framework_TestCase
{
    public function testValidResponse()
    {
        $plugin = new Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new Guzzle\Http\Message\Response(200, null, '{"active": true}'));
        $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $this->assertInstanceOf("\\fkooman\\oauth\\rs\\TokenIntrospection", $rs->verifyRequest("Bearer 001"));
    }

    /**
     * @expectedException \fkooman\oauth\rs\ResourceServerException
     * @expectedExceptionMessage internal_server_error
     */
    public function testNoJsonResponse()
    {
        $plugin = new Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new Guzzle\Http\Message\Response(200, null, 'BROKEN'));
        $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
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
        $plugin = new Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new Guzzle\Http\Message\Response(200, null, 'true'));
        $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
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
        $plugin = new Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new Guzzle\Http\Message\Response(404, null, 'Not Found'));
        $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
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
        $rs = new ResourceServer(new Guzzle\Http\Client());
        $introspection = $rs->verifyRequest("Bearer 003", "003");
    }

    /**
     * @expectedException \fkooman\oauth\rs\ResourceServerException
     * @expectedExceptionMessage no_token
     */
    public function testNoTokenMethods()
    {
        $rs = new ResourceServer(new Guzzle\Http\Client());
        $introspection = $rs->verifyRequest();
    }

    /**
     * @expectedException \fkooman\oauth\rs\ResourceServerException
     * @expectedExceptionMessage invalid_token
     */
    public function testNotBearerAuthorizationHeader()
    {
        $rs = new ResourceServer(new Guzzle\Http\Client());
        $introspection = $rs->verifyRequest("Basic Zm9vOmJhcg==");
    }

    /**
     * @expectedException \fkooman\oauth\rs\ResourceServerException
     * @expectedExceptionMessage invalid_token
     */
    public function testInvalidTokenCharacters()
    {
        $rs = new ResourceServer(new Guzzle\Http\Client());
        $introspection = $rs->verifyRequest(null, ",./'_=09211#4$");
    }
}
