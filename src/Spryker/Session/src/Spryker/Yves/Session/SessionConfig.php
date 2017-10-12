<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Session;

use Spryker\Shared\Session\SessionConstants;
use Spryker\Yves\Kernel\AbstractBundleConfig;

class SessionConfig extends AbstractBundleConfig
{
    const PROTOCOL_TCP = 'tcp';

    const DATA_SOURCE_NAME_TEMPLATE_TCP = 'tcp://[host]:[port]?database=[database][authFragment]';
    const AUTH_FRAGMENT_TEMPLATE_TCP = '&password=%s';

    const DATA_SOURCE_NAME_TEMPLATE_REDIS = 'redis://[authFragment][host]:[port]/[database]';
    const AUTH_FRAGMENT_TEMPLATE_REDIS = ':%s@';

    /**
     * Default Redis database number
     */
    const DEFAULT_REDIS_DATABASE = 0;

    /**
     * @return array
     */
    public function getSessionStorageOptions()
    {
        $sessionStorageOptions = [
            'name' => str_replace('.', '-', $this->get(SessionConstants::YVES_SESSION_COOKIE_NAME)),
            'cookie_lifetime' => $this->getSessionCookieTimeToLive(),
            'cookie_secure' => $this->secureCookie(),
            'cookie_httponly' => true,
        ];

        $cookieDomain = $this->get(SessionConstants::YVES_SESSION_COOKIE_DOMAIN);
        if ($cookieDomain) {
            $sessionStorageOptions['cookie_domain'] = $cookieDomain;
        }

        return $sessionStorageOptions;
    }

    /**
     * Projects should use `SessionConstants::YVES_SESSION_COOKIE_TIME_TO_LIVE`. If they don't have it in
     * their config we will use the existing `SessionConstants::YVES_SESSION_TIME_TO_LIVE` as default value.
     *
     * @return int
     */
    private function getSessionCookieTimeToLive()
    {
        return (int)$this->get(SessionConstants::YVES_SESSION_COOKIE_TIME_TO_LIVE, $this->get(SessionConstants::YVES_SESSION_TIME_TO_LIVE));
    }

    /**
     * @return bool
     */
    protected function secureCookie()
    {
        return ($this->get(SessionConstants::YVES_SESSION_COOKIE_SECURE, true) && $this->get(SessionConstants::YVES_SSL_ENABLED, true));
    }

    /**
     * @return string
     */
    public function getConfiguredSessionHandlerName()
    {
        return $this->get(SessionConstants::YVES_SESSION_SAVE_HANDLER);
    }

    /**
     * @return int
     */
    public function getSessionLifeTime()
    {
        return (int)$this->get(SessionConstants::YVES_SESSION_TIME_TO_LIVE);
    }

    /**
     * @return string
     */
    public function getSessionHandlerRedisDataSourceName()
    {
        return $this->buildDataSourceName(
            $this->get(SessionConstants::YVES_SESSION_REDIS_PROTOCOL),
            $this->get(SessionConstants::YVES_SESSION_REDIS_HOST),
            $this->get(SessionConstants::YVES_SESSION_REDIS_PORT),
            $this->get(SessionConstants::YVES_SESSION_REDIS_DATABASE, static::DEFAULT_REDIS_DATABASE),
            $this->get(SessionConstants::YVES_SESSION_REDIS_PASSWORD, false)
        );
    }

    /**
     * @param string $protocol
     * @param string $host
     * @param int $port
     * @param int $database
     * @param string $password
     *
     * @return string
     */
    protected function buildDataSourceName($protocol, $host, $port, $database, $password)
    {
        $authFragmentTemplate = $this->getAuthFragmentTemplate($protocol);
        $dataSourceNameTemplate = $this->getDataSourceNameTemplate($protocol);
        $authFragment = '';
        if ($password) {
            $authFragment = sprintf($authFragmentTemplate, $password);
        }

        $dataSourceNameElements = [
            '[host]' => $host,
            '[port]' => $port,
            '[database]' => $database,
            '[authFragment]' => $authFragment,
        ];

        return str_replace(
            array_keys($dataSourceNameElements),
            array_values($dataSourceNameElements),
            $dataSourceNameTemplate
        );
    }

    /**
     * @param string $protocol
     *
     * @return string
     */
    protected function getAuthFragmentTemplate($protocol)
    {
        return ($protocol === static::PROTOCOL_TCP) ? static::AUTH_FRAGMENT_TEMPLATE_TCP : static::AUTH_FRAGMENT_TEMPLATE_REDIS;
    }

    /**
     * @param string $protocol
     *
     * @return string
     */
    protected function getDataSourceNameTemplate($protocol)
    {
        return ($protocol === static::PROTOCOL_TCP) ? static::DATA_SOURCE_NAME_TEMPLATE_TCP : static::DATA_SOURCE_NAME_TEMPLATE_REDIS;
    }

    /**
     * @return string
     */
    public function getSessionHandlerFileSavePath()
    {
        return $this->get(SessionConstants::YVES_SESSION_FILE_PATH);
    }
}
