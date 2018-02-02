<?php
require __DIR__ . '/../vendor/autoload.php';

use fkooman\OAuth\ResourceServer\ResourceServer;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7;

$client_id = 'dev.api-ged.tms-soft.fr/oauth';
$client_secret = 'tm7';

$resourceServer = new ResourceServer(
    new \GuzzleHttp\Client([
        'base_uri' => "http://cas.intra.misiv.fr:8088"
    ])
);

$resourceServer->setAuthorizationHeader(
    "Bearer AT-15-M-ch1vOur3IjB9xaM2k-AQGwoM1IiKJa"
);

$tokenIntrospection = $resourceServer->verifyToken(function ($token) use ($client_id, $client_secret) {
    $request = new Request('POST', '/cas/oidc/introspect', [
        'Content-Type' => 'application/x-www-form-urlencoded',
        'Authorization' => sprintf('Basic %s', base64_encode("$client_id:$client_secret"))
    ]);

    return $request->withBody(Psr7\stream_for(http_build_query([ 'access_token' => $token])));
});

var_dump($tokenIntrospection);