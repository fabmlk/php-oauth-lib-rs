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
    /**
     * @dataProvider validTokenProvider
     */
    public function testTokenIntrospectionTest($token, $active, $expiresAt, $issuedAt, $scope, $clientId, $sub, $aud, $tokenType)
    {
        $i = new TokenIntrospection($token);
        $this->assertEquals($active, $i->getActive());
        $this->assertEquals($expiresAt, $i->getExpiresAt());
        $this->assertEquals($issuedAt, $i->getIssuedAt());
        $this->assertEquals($scope, $i->getScope());
        $this->assertEquals($clientId, $i->getClientId());
        $this->assertEquals($sub, $i->getSub());
        $this->assertEquals($aud, $i->getAud());
        $this->assertEquals($tokenType, $i->getTokenType());
        $this->assertEquals($token, $i->getToken());
    }

    public function validTokenProvider()
    {
        $iat = time();
        $exp = $iat + 100;

        return array(
            array(
                array("active" => false),
                false, false, false, false, false, false, false, false,
            ),

            array(
                array("active" => true, "exp" => $exp, "iat" => $iat, "scope" => "read write", "client_id" => "foo", "sub" => "fkooman", "aud" => "foobar", "token_type" => "bearer"),
                true, $exp, $iat, "read write", "foo", "fkooman", "foobar", "bearer"
            )
        );
    }

}
