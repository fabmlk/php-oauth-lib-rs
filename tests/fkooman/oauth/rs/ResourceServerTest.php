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
    public function testBasic()
    {
        $plugin = new Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new Guzzle\Http\Message\Response(200, null, '{"active": true}'));
        $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $introspect = $rs->verifyRequest("Bearer 001");
        $this->assertTrue($introspect->getActive());
    }

    public function testBasicToken()
    {
        $plugin = new Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new Guzzle\Http\Message\Response(200, null, $this->getFile("001")));
        $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);

        $introspection = $rs->verifyRequest("Bearer 001");
        $this->assertEquals("fkooman", $introspection->getSub());
        $this->assertEquals("testclient", $introspection->getClientId());
        $this->assertEquals(1766377846, $introspection->getExpiresAt());
        $this->assertEquals(1366376612, $introspection->getIssuedAt());
        $this->assertEquals("foo bar", $introspection->getScope());
        $this->assertTrue($introspection->getActive());
    }

    private function getFile($file)
    {
        return file_get_contents(dirname(dirname(dirname(__DIR__))) . DIRECTORY_SEPARATOR . "data" . DIRECTORY_SEPARATOR . $file . ".json");
    }

    public function testBasicTokenNoEntitlement()
    {
        $plugin = new Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new Guzzle\Http\Message\Response(200, null, $this->getFile("002")));
        $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);

        $introspection = $rs->verifyRequest(null, "002");
        $this->assertEquals("frko", $introspection->getSub());
        $this->assertEquals("testclient", $introspection->getClientId());
        $this->assertEquals(1766377846, $introspection->getExpiresAt());
        $this->assertEquals(1366376612, $introspection->getIssuedAt());
        $this->assertEquals("a b c", $introspection->getScope());
        $this->assertTrue($introspection->getActive());
    }

    public function testInvalidToken()
    {
        $plugin = new Guzzle\Plugin\Mock\MockPlugin();
        $plugin->addResponse(new Guzzle\Http\Message\Response(200, null, $this->getFile("003")));
        $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
        $client->addSubscriber($plugin);
        $rs = new ResourceServer($client);
        $introspection = $rs->verifyRequest(null, "003");
        $this->assertFalse($introspection->getActive());
        $this->assertFalse($introspection->getSub());
    }

    public function testInvalidIntrospectionResponse()
    {
        try {
            $plugin = new Guzzle\Plugin\Mock\MockPlugin();
            $plugin->addResponse(new Guzzle\Http\Message\Response(200, null, $this->getFile("100")));
            $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
            $client->addSubscriber($plugin);
            $rs = new ResourceServer($client);
            $introspection = $rs->verifyRequest("Bearer 100");
            $this->assertTrue(false);
        } catch (ResourceServerException $e) {
            $this->assertEquals("internal_server_error", $e->getMessage());
            $this->assertEquals("active key should be set and its value a boolean", $e->getDescription());
            $this->assertEquals(500, $e->getStatusCode());
            $this->assertNull($e->getAuthenticateHeader());
        }
    }

/*
    // FIXME: this returns a Guzzle error, not a tokenintrospection error
    public function testNoJsonResponse()
    {
        try {
            $plugin = new Guzzle\Plugin\Mock\MockPlugin();
            $plugin->addResponse(new Guzzle\Http\Message\Response(200, null, $this->getFile("101")));
            $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
            $client->addSubscriber($plugin);
            $rs = new ResourceServer($client);

            $introspection = $rs->verifyRequest("Bearer 101");
            $this->assertTrue(false);
        } catch (ResourceServerException $e) {
            $this->assertEquals("internal_server_error", $e->getMessage());
            $this->assertEquals("unable to decode response from introspection endpoint", $e->getDescription());
            $this->assertEquals(500, $e->getStatusCode());
            $this->assertNull($e->getAuthenticateHeader());
        }
    }
*/

    public function testMultipleBearerTokens()
    {
        try {
            $plugin = new Guzzle\Plugin\Mock\MockPlugin();
            $plugin->addResponse(new Guzzle\Http\Message\Response(200, null, $this->getFile("003")));
            $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
            $client->addSubscriber($plugin);
            $rs = new ResourceServer($client);

            $introspection = $rs->verifyRequest("Bearer 003", "003");
            $this->assertTrue(false);
        } catch (ResourceServerException $e) {
            $this->assertEquals("invalid_request", $e->getMessage());
            $this->assertEquals("more than one method for including an access token used", $e->getDescription());
            $this->assertEquals(400, $e->getStatusCode());
            $this->assertEquals('Bearer realm="Resource Server",error="invalid_request",error_description="more than one method for including an access token used"', $e->getAuthenticateHeader());
        }
    }

    public function testNoBearerTokens()
    {
        try {
            $plugin = new Guzzle\Plugin\Mock\MockPlugin();
            $plugin->addResponse(new Guzzle\Http\Message\Response(200, null, $this->getFile("003")));
            $client = new Guzzle\Http\Client("https://auth.example.org/introspect");
            $client->addSubscriber($plugin);
            $rs = new ResourceServer($client);
            $introspection = $rs->verifyRequest(array(), array());
            $this->assertTrue(false);
        } catch (ResourceServerException $e) {
            $this->assertEquals("no_token", $e->getMessage());
            $this->assertEquals("missing token", $e->getDescription());
            $this->assertEquals(401, $e->getStatusCode());
            $this->assertEquals('Bearer realm="Resource Server"', $e->getAuthenticateHeader());
        }
    }

}
