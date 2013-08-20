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

use fkooman\oauth\rs\ResourceServerException;

class ResourceServerExceptionTest extends PHPUnit_Framework_TestCase
{
    public function testBasic()
    {
        $e = new ResourceServerException("invalid_token", "the token is invalid");
        $e->setRealm("Foo");
        $this->assertEquals("Foo", $e->getRealm());
        $this->assertEquals(401, $e->getStatusCode());
        $this->assertEquals("invalid_token", $e->getMessage());
        $this->assertEquals("the token is invalid", $e->getDescription());
        $this->assertEquals('Bearer realm="Foo",error="invalid_token",error_description="the token is invalid"', $e->getAuthenticateHeader());
    }

    public function testNoToken()
    {
        $e = new ResourceServerException("no_token", "the token is missing");
        $e->setRealm("Foo");
        $this->assertEquals("Foo", $e->getRealm());
        $this->assertEquals(401, $e->getStatusCode());
        $this->assertEquals("no_token", $e->getMessage());
        $this->assertEquals("the token is missing", $e->getDescription());
        $this->assertEquals('Bearer realm="Foo"', $e->getAuthenticateHeader());
    }

}
