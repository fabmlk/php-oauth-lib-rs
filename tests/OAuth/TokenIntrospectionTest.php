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

use \OAuth\TokenIntrospection as TokenIntrospection;
use \OAuth\RemoteResourceServerException as RemoteResourceServerException;

class TokenIntrospectionTest extends PHPUnit_Framework_TestCase
{

    /**
     * @dataProvider validTokenProvider
     */
    public function testTokenIntrospectionTest($token, $active, $expiresAt, $issuedAt, $scope, $clientId, $sub, $aud)
    {
        $i = new TokenIntrospection($token);
        $this->assertEquals($active, $i->getActive());
        $this->assertEquals($expiresAt, $i->getExpiresAt());
        $this->assertEquals($issuedAt, $i->getIssuedAt());
        $this->assertEquals($scope, $i->getScope());
        if (FALSE !== $i->getScope()) {
            $eScope = explode(" ", $i->getScope());
            $this->assertEquals($eScope, $i->getScopeAsArray());
            for ( $j = 0; $j < count($eScope); $j++) {
                $this->assertTrue($i->hasScope($eScope[$j]));
                $this->assertTrue($i->hasAnyScope(array($eScope[$j], "bogus")));
                $i->requireScope($eScope[$j]);
            }
        }
        $this->assertEquals($clientId, $i->getClientId());
        $this->assertEquals($sub, $i->getResourceOwnerId());
        $this->assertEquals($sub, $i->getSub());
        $this->assertEquals($aud, $i->getAud());
        try {
            $i->requireScope("bogus");
            $this->assertTrue(FALSE);
        } catch (RemoteResourceServerException $e) {
        }
        $this->assertFalse($i->hasAnyScope(array("foo")));
    }

    public function validTokenProvider()
    {
        return array(
            array(
                array("active" => TRUE),
                TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE
            ),

            array(
                array("active" => TRUE, "expires_at" => 12345, "issued_at" => 1234, "scope" => "read write", "client_id" => "foo", "sub" => "fkooman", "aud" => "foobar"),
                TRUE, 12345, 1234, "read write", "foo", "fkooman", "foobar"
            ),
        );
    }

}
