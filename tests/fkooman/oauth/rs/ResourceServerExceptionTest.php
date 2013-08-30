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

class ResourceServerExceptionTest extends \PHPUnit_Framework_TestCase
{
    public function testBasic()
    {
        $e = new ResourceServerException("invalid_token", "the token is invalid");
        $e->setRealm("Foo");
        $this->assertEquals("Foo", $e->getRealm());
        $this->assertEquals(401, $e->getStatusCode());
        $this->assertEquals("invalid_token", $e->getMessage());
        $this->assertEquals("the token is invalid", $e->getDescription());
        $this->assertEquals(
            'Bearer realm="Foo",error="invalid_token",error_description="the token is invalid"',
            $e->getAuthenticateHeader()
        );
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

    public function testInternalServerError()
    {
        $e = new ResourceServerException("internal_server_error", "something really bad happened");
        $this->assertEquals("Resource Server", $e->getRealm());
        $this->assertEquals(500, $e->getStatusCode());
        $this->assertEquals("internal_server_error", $e->getMessage());
        $this->assertEquals("something really bad happened", $e->getDescription());
        $this->assertNull($e->getAuthenticateHeader());
    }

    public function testInsufficientScope()
    {
        $e = new ResourceServerException("insufficient_scope", "scope 'foo' required");
        $this->assertEquals(403, $e->getStatusCode());
        $this->assertEquals(
            'Bearer realm="Resource Server",error="insufficient_scope",error_description="scope \'foo\' required"',
            $e->getAuthenticateHeader()
        );
    }

    public function testInvalidRequest()
    {
        $e = new ResourceServerException("invalid_request", "request not valid");
        $this->assertEquals(400, $e->getStatusCode());
    }

    public function testUnsupportedType()
    {
        $e = new ResourceServerException("foo", "bar");
        $this->assertEquals(400, $e->getStatusCode());
    }
}
