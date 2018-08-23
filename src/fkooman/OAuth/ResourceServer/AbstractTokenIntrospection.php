<?php

namespace fkooman\OAuth\ResourceServer;

use fkooman\OAuth\Common\Scope;

/**
 * Class AbstractTokenIntrospection.
 */
abstract class AbstractTokenIntrospection
{
    /**
     * @var array
     */
    protected $response;

    /**
     * AbstractTokenIntrospection constructor.
     *
     * @param array $response
     */
    public function __construct(array $response)
    {
        $this->response = $response;

        $this->checkActive();
        $this->checkExpiresAt();
        $this->checkIssuedAt();
    }

    /**
     * REQUIRED. Check active field is correctly formatted.
     */
    abstract public function checkActive();

    /**
     * REQUIRED. Check iat field is correctly formatted.
     */
    abstract public function checkExpiresAt();

    /**
     * REQUIRED. Check Scope is correctly formatted.
     */
    abstract public function checkIssuedAt();

    /**
     * REQUIRED. Check Scope is correctly formatted.
     */
    abstract public function checkScope();

    /**
     * @return bool
     */
    abstract public function isActive();

    /**
     * @return bool
     */
    abstract public function isExpired();

    /**
     * REQUIRED.  Boolean indicator of whether or not the presented
     * token is currently active.
     */
    public function getActive()
    {
        return isset($this->response['active']) ? $this->response['active'] : null;
    }

    /**
     * OPTIONAL.  Integer timestamp, measured in the number of
     * seconds since January 1 1970 UTC, indicating when this token will
     * expire.
     */
    public function getExpiresAt()
    {
        return $this->getKeyValue('exp');
    }

    /**
     * OPTIONAL.  Integer timestamp, measured in the number of
     * seconds since January 1 1970 UTC, indicating when this token was
     * originally issued.
     */
    public function getIssuedAt()
    {
        return $this->getKeyValue('iat');
    }

    /**
     * OPTIONAL.  A space-separated list of strings representing the
     * scopes associated with this token, in the format described in
     * Section 3.3 of OAuth 2.0 [RFC6749].
     *
     * @return Scope
     * @throws \fkooman\OAuth\Common\Exception\ScopeException
     */
    public function getScope()
    {
        $scopeValue = $this->getKeyValue('scope');
        if (false === $scopeValue) {
            return new Scope();
        }

        return Scope::fromString($scopeValue);
    }

    /**
     * OPTIONAL.  Client Identifier for the OAuth Client that
     * requested this token.
     */
    public function getClientId()
    {
        return $this->getKeyValue('client_id');
    }

    /**
     * OPTIONAL.  Local identifier of the Resource Owner who authorized
     * this token.
     */
    public function getSub()
    {
        return $this->getKeyValue('sub');
    }

    /**
     * OPTIONAL.  Service-specific string identifier or list of string
     * identifiers representing the intended audience for this token.
     */
    public function getAud()
    {
        return $this->getKeyValue('aud');
    }

    /**
     * OPTIONAL.  Type of the token as defined in OAuth 2.0
     * section 5.1.
     */
    public function getTokenType()
    {
        return $this->getKeyValue('token_type');
    }

    /**
     * Get the complete response from the introspection endpoint
     */
    public function getToken()
    {
        return $this->response;
    }

    /**
     * @param $key
     *
     * @return bool|mixed
     */
    protected function getKeyValue($key)
    {
        if (!isset($this->response[$key])) {
            return false;
        }

        return $this->response[$key];
    }
}
