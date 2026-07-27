<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Security\Loader\Services;

use Spryker\Service\Container\ContainerInterface;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserProviderPrototypeServiceLoader implements ServiceLoaderInterface
{
    /**
     * @var string
     */
    protected const SERVICE_SECURITY_USER_PROVIDER_INMEMORY_PROTO = 'security.user_provider.inmemory._proto';

    /**
     * @var int
     */
    protected const INDEX_USER_ROLES = 0;

    /**
     * @var int
     */
    protected const INDEX_USER_PASSWORD = 1;

    /**
     * @var string
     */
    protected const KEY_USER_ROLES = 'roles';

    /**
     * @var string
     */
    protected const KEY_USER_PASSWORD = 'password';

    public function add(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_USER_PROVIDER_INMEMORY_PROTO, $container->protect(function (array $params): callable {
            return function () use ($params): UserProviderInterface {
                $users = [];

                /** @var string $name */
                foreach ($params as $name => $user) {
                    $roles = array_values(array_map(
                        static fn ($role): string => (string)$role,
                        (array)$user[static::INDEX_USER_ROLES],
                    ));

                    $users[$name] = [
                        static::KEY_USER_ROLES => $roles,
                        static::KEY_USER_PASSWORD => (string)$user[static::INDEX_USER_PASSWORD],
                    ];
                }

                /** @var array<string, array{roles: list<string>, password: string}> $users */
                return new InMemoryUserProvider($users);
            };
        }));

        return $container;
    }
}
