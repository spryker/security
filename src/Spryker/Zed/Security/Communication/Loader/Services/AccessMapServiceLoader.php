<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Security\Communication\Loader\Services;

use Spryker\Service\Container\ContainerInterface;
use Spryker\Zed\Security\Communication\Configurator\SecurityConfiguratorInterface;
use Symfony\Component\HttpFoundation\ChainRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\AttributesRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\HostRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\IpsRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\MethodRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\PathRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\SchemeRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;
use Symfony\Component\Security\Http\AccessMap;
use Symfony\Component\Security\Http\AccessMapInterface;

class AccessMapServiceLoader implements ServiceLoaderInterface
{
    /**
     * @var string
     */
    protected const SERVICE_SECURITY_ACCESS_MAP = 'security.access_map';

    /**
     * @var \Spryker\Zed\Security\Communication\Configurator\SecurityConfiguratorInterface
     */
    protected SecurityConfiguratorInterface $securityConfigurator;

    public function __construct(SecurityConfiguratorInterface $securityConfigurator)
    {
        $this->securityConfigurator = $securityConfigurator;
    }

    public function add(ContainerInterface $container): ContainerInterface
    {
        $container->set(static::SERVICE_SECURITY_ACCESS_MAP, function (ContainerInterface $container): AccessMapInterface {
            $map = new AccessMap();
            $accessRules = $this->securityConfigurator->getSecurityConfiguration($container)->getAccessRules();
            $ruleMappings = $this->mapRules();

            foreach ($accessRules as $rule) {
                $ruleType = gettype($rule[0]);

                if (isset($ruleMappings[$ruleType])) {
                    $map->add($ruleMappings[$ruleType]($rule[0]), (array)$rule[1], $rule[2] ?? null);
                }
            }

            return $map;
        });

        return $container;
    }

    /**
     * @return array<mixed>
     */
    protected function mapRules(): array
    {
        return [
            'string' => function (string $rule): RequestMatcherInterface {
                return $this->buildRequestMatcher($rule);
            },
            'array' => function (array $rule): RequestMatcherInterface {
                $rule += [
                    'path' => null,
                    'host' => null,
                    'methods' => null,
                    'ips' => null,
                    'attributes' => [],
                    'schemes' => null,
                ];

                return $this->buildRequestMatcher(
                    $rule['path'],
                    $rule['host'],
                    $rule['methods'],
                    $rule['ips'],
                    $rule['attributes'],
                    $rule['schemes'],
                );
            },
        ];
    }

    /**
     * @param array<string>|string|null $methods
     * @param array<string>|string|null $ips
     * @param array<string, string>|null $attributes
     * @param array<string>|string|null $schemes
     */
    protected function buildRequestMatcher(
        ?string $path = null,
        ?string $host = null,
        array|string|null $methods = null,
        array|string|null $ips = null,
        ?array $attributes = null,
        array|string|null $schemes = null
    ): RequestMatcherInterface {
        $matchers = [];

        if ($path) {
            $matchers[] = new PathRequestMatcher($path);
        }

        if ($host) {
            $matchers[] = new HostRequestMatcher($host);
        }

        if ($methods) {
            $matchers[] = new MethodRequestMatcher($methods);
        }

        if ($ips) {
            $matchers[] = new IpsRequestMatcher($ips);
        }

        if ($attributes) {
            $matchers[] = new AttributesRequestMatcher($attributes);
        }

        if ($schemes) {
            $matchers[] = new SchemeRequestMatcher($schemes);
        }

        return new ChainRequestMatcher($matchers);
    }
}
