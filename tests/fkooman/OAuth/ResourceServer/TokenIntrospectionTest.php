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

class TokenIntrospectionTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException fkooman\OAuth\ResourceServer\TokenIntrospectionException
     * @expectedExceptionMessage the token is not active
     */
    public function testNotActive()
    {
        $t = new TokenIntrospection(array("active" => false, "sub" => "foo"));
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
     * @expectedException fkooman\OAuth\ResourceServer\TokenIntrospectionException
     * @expectedExceptionMessage active key should be set and its value a boolean
     */
    public function testMissingActive()
    {
        $t = new TokenIntrospection(array());
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\TokenIntrospectionException
     * @expectedExceptionMessage the token expired
     */
    public function testExpired()
    {
        $t = new TokenIntrospection(array("active" => true, "exp" => time()-1000));
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\TokenIntrospectionException
     * @expectedExceptionMessage token issued in the future
     */
    public function testIssueTimeInFuture()
    {
        $t = new TokenIntrospection(array("active" => true, "iat" => time()+1000));
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\TokenIntrospectionException
     * @expectedExceptionMessage token expired before it was issued
     */
    public function testExpiresBeforeIssued()
    {
        $t = new TokenIntrospection(array("active" => true, "iat" => time()-500, "exp" => time()-1000));
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\TokenIntrospectionException
     * @expectedExceptionMessage iat value must be positive integer
     */
    public function testNegativeIssueTime()
    {
        $t = new TokenIntrospection(array("active" => true, "iat" => -4));
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\TokenIntrospectionException
     * @expectedExceptionMessage iat value must be positive integer
     */
    public function testNonIntIssueTime()
    {
        $t = new TokenIntrospection(array("active" => true, "iat" => "1234567"));
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\TokenIntrospectionException
     * @expectedExceptionMessage exp value must be positive integer
     */
    public function testNonIntExpiryTime()
    {
        $t = new TokenIntrospection(array("active" => true, "exp" => "1234567"));
    }

    /**
     * @expectedException fkooman\OAuth\ResourceServer\TokenIntrospectionException
     * @expectedExceptionMessage exp value must be positive integer
     */
    public function testNegativeExpiryTime()
    {
        $t = new TokenIntrospection(array("active" => true, "exp" => -4));
    }
}
