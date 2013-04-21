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

require_once dirname(dirname(__DIR__)) . DIRECTORY_SEPARATOR . "lib" . DIRECTORY_SEPARATOR . "OAuth" . DIRECTORY_SEPARATOR . "RemoteResourceServer.php";

use \OAuth\RemoteResourceServer as RemoteResourceServer;
use \OAuth\RemoteResourceServerException as RemoteResourceServerException;

class RemoteResourceServerTest extends PHPUnit_Framework_TestCase
{

    private $_dataPath;

    public function setUp()
    {
        $this->_dataPath = "file://" . dirname(__DIR__) . DIRECTORY_SEPARATOR . "data/";
    }

    public function testBasicToken()
    {
        $config = array(
            "introspectionEndpoint" => $this->_dataPath,
            "realm" => "Foo"
        );
        $rs = new RemoteResourceServer($config);
        $introspection = $rs->verifyRequest(array("Authorization" => "Bearer 001"), array());
        $this->assertEquals("fkooman", $introspection->getSub());
        $this->assertEquals("testclient", $introspection->getClientId());
        $this->assertEquals(1366377846, $introspection->getExpiresAt());
        $this->assertEquals(1366376612, $introspection->getIssuedAt());
        $this->assertEquals("foo bar", $introspection->getScope());
        $this->assertEquals("urn:x-foo:service:access urn:x-bar:privilege:admin", $introspection->getEntitlement());
        $this->assertTrue($introspection->getActive());
    }

    public function testBasicTokenNoEntitlement()
    {
        $config = array(
            "introspectionEndpoint" => $this->_dataPath,
            "realm" => "Foo"
        );
        $rs = new RemoteResourceServer($config);
        $introspection = $rs->verifyRequest(array(), array("access_token" => "002"));
        $this->assertEquals("frko", $introspection->getSub());
        $this->assertEquals("testclient", $introspection->getClientId());
        $this->assertEquals(1366377846, $introspection->getExpiresAt());
        $this->assertEquals(1366376612, $introspection->getIssuedAt());
        $this->assertEquals("a b c", $introspection->getScope());
        $this->assertFalse($introspection->getEntitlement());
        $this->assertTrue($introspection->getActive());
    }

    public function testInvalidToken()
    {
        $config = array(
            "introspectionEndpoint" => $this->_dataPath,
            "realm" => "Foo"
        );
        try {
            $rs = new RemoteResourceServer($config);
            $introspection = $rs->verifyRequest(array(), array("access_token" => "003"));
            $this->assertTrue(FALSE);
        } catch (RemoteResourceServerException $e) {
            $this->assertEquals("invalid_token", $e->getMessage());
            $this->assertEquals("the token is not active", $e->getDescription());
            $this->assertEquals(401, $e->getResponseCode());
            $this->assertEquals('Bearer realm="Resource Server",error="invalid_token",error_description="the token is not active"', $e->getAuthenticateHeader());
        }
    }

    public function testInvalidIntrospectionResponse()
    {
        $config = array(
            "introspectionEndpoint" => $this->_dataPath,
            "realm" => "Foo"
        );
        try {
            $rs = new RemoteResourceServer($config);
            $introspection = $rs->verifyRequest(array("Authorization" => "Bearer 100"), array());
            $this->assertTrue(FALSE);
        } catch (RemoteResourceServerException $e) {
            $this->assertEquals("internal_server_error", $e->getMessage());
            $this->assertEquals("malformed response from introspection endpoint", $e->getDescription());
            $this->assertEquals(500, $e->getResponseCode());
            $this->assertNull($e->getAuthenticateHeader());
        }
    }
}
