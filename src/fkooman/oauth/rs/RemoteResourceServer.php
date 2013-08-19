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

    /**
     * @param string authorizationHeader
     *     the value of the Authorzation header in the form: "Bearer xyz"
     * @param string accessTokenQueryParameter
     *     the value of the "access_token" query parameter in the form: "xyz"
     */
    public function verifyRequest($authorizationHeader = null, $accessTokenQueryParameter = null)
    {
        if (empty($authorizationHeader) && empty($accessTokenQueryParameter)) {
            // no token
            throw new RemoteResourceServerException("no_token", "missing token");
        }

        if (!empty($authorizationHeader) && !empty($accessTokenQueryParameter)) {
            // two tokens provided
            throw new RemoteResourceServerException("invalid_request", "more than one method for including an access token used");
        }

        if (!empty($authorizationHeader)) {
            if (0 !== stripos($authorizationHeader, "Bearer ")) {
                throw new RemoteResourceServerException("invalid_token", "not a bearer token");
            }

            return $this->verifyBearerToken(substr($authorizationHeader, 7));
        }
        if (!empty($accessTokenQueryParameter)) {
            return $this->verifyBearerToken($accessTokenQueryParameter);
        }
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
