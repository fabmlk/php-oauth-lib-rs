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

use fkooman\oauth\rs\TokenIntrospection;

class TokenIntrospectionTest extends PHPUnit_Framework_TestCase
{
    public function testNotActive()
    {
        $t = new TokenIntrospection(array("active" => false, "sub" => "foo"));
        $this->assertFalse($t->getActive());
        // when not active, other fields must return false
        $this->assertFalse($t->getSub());
    }

    public function testComplete()
    {
        $now = time();

        $t = new TokenIntrospection(
            array(
                "active" => true,
                "exp" => $now + 1000,
                "iat" => $now - 1000,
                "sub" => "foo",
                "client_id" => "bar",
                "aud" => "foobar",
                "scope" => "foo bar baz",
                "token_type" => "bearer",
                "x-ext" => array("proprietary", "extension", "data")
            )
        );
        $this->assertTrue($t->getActive());
        $this->assertEquals($now + 1000, $t->getExpiresAt());
        $this->assertEquals($now - 1000, $t->getIssuedAt());
        $this->assertEquals("foo", $t->getSub());
        $this->assertEquals("bar", $t->getClientId());
        $this->assertEquals("foobar", $t->getAud());
        $this->assertEquals("foo bar baz", $t->getScope());
        $this->assertEquals("bearer", $t->getTokenType());
        $token = $t->getToken();
        $this->assertEquals(array("proprietary", "extension", "data"), $token["x-ext"]);
    }

    public function testActive()
    {
        $t = new TokenIntrospection(array("active" => true));
        $this->assertTrue($t->getActive());
        // non exiting key should return false
        $this->assertFalse($t->getSub());
    }

    /**
     * @expectedException \fkooman\oauth\rs\TokenIntrospectionException
     * @expectedExceptionMessage active key should be set and its value a boolean
     */
    public function testMissingActive()
    {
        $t = new TokenIntrospection(array());
    }

    /**
     * @expectedException \fkooman\oauth\rs\TokenIntrospectionException
     * @expectedExceptionMessage the token expired
     */
    public function testExpired()
    {
        $t = new TokenIntrospection(array("active" => true, "exp" => time()-1000));
    }

    /**
     * @expectedException \fkooman\oauth\rs\TokenIntrospectionException
     * @expectedExceptionMessage token issued in the future
     */
    public function testIssueTimeInFuture()
    {
        $t = new TokenIntrospection(array("active" => true, "iat" => time()+1000));
    }

    /**
     * @expectedException \fkooman\oauth\rs\TokenIntrospectionException
     * @expectedExceptionMessage token expired before it was issued
     */
    public function testExpiresBeforeIssued()
    {
        $t = new TokenIntrospection(array("active" => true, "iat" => time()-500, "exp" => time()-1000));
    }

    /**
     * @expectedException \fkooman\oauth\rs\TokenIntrospectionException
     * @expectedExceptionMessage iat value must be positive integer
     */
    public function testNegativeIssueTime()
    {
        $t = new TokenIntrospection(array("active" => true, "iat" => -4));
    }

    /**
     * @expectedException \fkooman\oauth\rs\TokenIntrospectionException
     * @expectedExceptionMessage iat value must be positive integer
     */
    public function testNonIntIssueTime()
    {
        $t = new TokenIntrospection(array("active" => true, "iat" => "1234567"));
    }

    /**
     * @expectedException \fkooman\oauth\rs\TokenIntrospectionException
     * @expectedExceptionMessage exp value must be positive integer
     */
    public function testNonIntExpiryTime()
    {
        $t = new TokenIntrospection(array("active" => true, "exp" => "1234567"));
    }

    /**
     * @expectedException \fkooman\oauth\rs\TokenIntrospectionException
     * @expectedExceptionMessage exp value must be positive integer
     */
    public function testNegativeExpiryTime()
    {
        $t = new TokenIntrospection(array("active" => true, "exp" => -4));
    }
}
