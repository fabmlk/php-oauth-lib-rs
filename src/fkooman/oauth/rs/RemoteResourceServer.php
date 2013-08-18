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

class RemoteResourceServer
{
    private $config;

    public function __construct(array $c)
    {
        $this->config = $c;
    }

    public function verifyAndHandleRequest()
    {
        try {
            $headerBearerToken = null;
            $queryBearerToken = null;

            // look for headers
            if (function_exists("apache_request_headers")) {
                $headers = apache_request_headers();
            } elseif (isset($_SERVER)) {
                $headers = $_SERVER;
            } else {
                $headers = array();
            }

            // look for query parameters
            $query = (isset($_GET) && is_array($_GET)) ? $_GET : array();

            return $this->verifyRequest($headers, $query);

        } catch (RemoteResourceServerException $e) {
            // send response directly to client, halt execution of calling script as well
            $e->setRealm($this->getConfigParameter("realm", false, "Resource Server"));
            header("HTTP/1.1 " . $e->getResponseCode());
            if (null !== $e->getAuthenticateHeader()) {
                // for "internal_server_error" responses no WWW-Authenticate header is set
                header("WWW-Authenticate: " . $e->getAuthenticateHeader());
            }
            header("Content-Type: application/json");
            die($e->getContent());
        }
    }

    public function verifyRequest(array $headers, array $query)
    {
        // extract token from authorization header
        $authorizationHeader = self::getAuthorizationHeader($headers);
        $ah = false !== $authorizationHeader ? self::getTokenFromHeader($authorizationHeader) : false;

        // extract token from query parameters
        $aq = self::getTokenFromQuery($query);

        if (false === $ah && false === $aq) {
            // no token at all provided
            throw new RemoteResourceServerException("no_token", "missing token");
        }
        if (false !== $ah && false !== $aq) {
            // two tokens provided
            throw new RemoteResourceServerException("invalid_request", "more than one method for including an access token used");
        }
        if (false !== $ah) {
            return $this->verifyBearerToken($ah);
        }
        if (false !== $aq) {
            return $this->verifyBearerToken($aq);
        }
    }

    private static function getAuthorizationHeader(array $headers)
    {
        $headerKeys = array_keys($headers);
        foreach (array("X-Authorization", "Authorization") as $h) {
            $keyPositionInArray = array_search(strtolower($h), array_map('strtolower', $headerKeys));
            if (false === $keyPositionInArray) {
                continue;
            }

            return $headers[$headerKeys[$keyPositionInArray]];
        }

        return false;
    }

    private static function getTokenFromHeader($authorizationHeader)
    {
        if (0 !== strpos($authorizationHeader, "Bearer ")) {
            return false;
        }

        return substr($authorizationHeader, 7);
    }

    private static function getTokenFromQuery(array $queryParameters)
    {
        if (!isset($queryParameters) || empty($queryParameters['access_token'])) {
            return false;
        }

        return $queryParameters['access_token'];
    }

    public function verifyBearerToken($token)
    {
        // b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
        if (1 !== preg_match('|^[[:alpha:][:digit:]-._~+/]+=*$|', $token)) {
            throw new RemoteResourceServerException("invalid_token", "the access token is not a valid b64token");
        }

        $introspectionEndpoint = $this->getConfigParameter("introspectionEndpoint");
        $get = array("token" => $token);

        if (!function_exists("curl_init")) {
            throw new RemoteResourceServerException("internal_server_error", "php curl module not available");
        }

        $curlChannel = curl_init();
        if (false === $curlChannel) {
            throw new RemoteResourceServerException("internal_server_error", "unable to initialize curl");
        }

        if (0 !== strpos($introspectionEndpoint, "file://")) {
            $separator = (false === strpos($introspectionEndpoint, "?")) ? "?" : "&";
            $introspectionEndpoint .= $separator . http_build_query($get, null, "&");
        } else {
            // file cannot have query parameter, use accesstoken as JSON file instead
            $introspectionEndpoint .= $token . ".json";
        }

        $disableCertCheck = $this->getConfigParameter("disableCertCheck", false, false);
        $curlOptions = array(
            CURLOPT_URL => $introspectionEndpoint,
            //CURLOPT_FOLLOWLOCATION => 1,
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_SSL_VERIFYPEER => $disableCertCheck ? 0 : 1,
            CURLOPT_SSL_VERIFYHOST => $disableCertCheck ? 0 : 2,
        );

        if (false === curl_setopt_array($curlChannel, $curlOptions)) {
            throw new RemoteResourceServerException("internal_server_error", "unable to set curl options");
        }

        $output = curl_exec($curlChannel);

        if (false === $output) {
            $error = curl_error($curlChannel);
            throw new RemoteResourceServerException("internal_server_error", sprintf("unable to contact introspection endpoint [%s]", $error));
        }

        $httpCode = curl_getinfo($curlChannel, CURLINFO_HTTP_CODE);
        curl_close($curlChannel);

        if (0 !== strpos($introspectionEndpoint, "file://")) {
            // not a file
            if (200 !== $httpCode) {
                throw new RemoteResourceServerException("internal_server_error", "unexpected response code from introspection endpoint");
            }
        }

        $data = json_decode($output, true);
        $jsonError = json_last_error();
        if (JSON_ERROR_NONE !== $jsonError) {
            throw new RemoteResourceServerException("internal_server_error", "unable to decode response from introspection endpoint");
        }
        if (!is_array($data) || !isset($data['active']) || !is_bool($data['active'])) {
            throw new RemoteResourceServerException("internal_server_error", "unexpected response from introspection endpoint");
        }

        if (!$data['active']) {
            throw new RemoteResourceServerException("invalid_token", "the token is not active");
        }

        return new TokenIntrospection($data);
    }

    private function getConfigParameter($key, $required = true, $default = null)
    {
        if (!array_key_exists($key, $this->config)) {
            if ($required) {
                throw new RemoteResourceServerException("internal_server_error", "missing required configuration parameter");
            } else {
                return $default;
            }
        }

        return $this->config[$key];
    }
}
