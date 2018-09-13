<?php
/**
 * Copyright © 2017-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\GlueApplication\Rest;

use Spryker\Glue\GlueApplication\Rest\Request\HttpRequestValidatorInterface;
use Spryker\Glue\GlueApplication\Rest\Uri\UriParserInterface;
use Spryker\Glue\Kernel\Application;
use Spryker\Glue\Kernel\BundleControllerAction;
use Spryker\Glue\Kernel\ClassResolver\Controller\ControllerResolver;
use Spryker\Glue\Kernel\Controller\RouteNameResolver;
use Spryker\Shared\Application\Communication\ControllerServiceBuilder;
use Symfony\Component\HttpFoundation\Request;

class ResourceRouter implements ResourceRouterInterface
{
    /**
     * @var \Spryker\Glue\GlueApplication\Rest\Request\HttpRequestValidatorInterface
     */
    protected $requestHeaderValidator;

    /**
     * @var \Spryker\Glue\Kernel\Application
     */
    protected $application;

    /**
     * @var \Spryker\Glue\GlueApplication\Rest\Uri\UriParserInterface
     */
    protected $uriParser;

    /**
     * @var \Spryker\Glue\GlueApplication\Rest\ResourceRouteLoaderInterface
     */
    protected $resourceRouteLoader;

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\Request\HttpRequestValidatorInterface $requestHeaderValidator
     * @param \Spryker\Glue\Kernel\Application $application
     * @param \Spryker\Glue\GlueApplication\Rest\Uri\UriParserInterface $uriParser
     * @param \Spryker\Glue\GlueApplication\Rest\ResourceRouteLoaderInterface $resourceRouteLoader
     */
    public function __construct(
        HttpRequestValidatorInterface $requestHeaderValidator,
        Application $application,
        UriParserInterface $uriParser,
        ResourceRouteLoaderInterface $resourceRouteLoader
    ) {
        $this->requestHeaderValidator = $requestHeaderValidator;
        $this->application = $application;
        $this->uriParser = $uriParser;
        $this->resourceRouteLoader = $resourceRouteLoader;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $httpRequest
     *
     * @return array
     */
    public function matchRequest(Request $httpRequest): array
    {
        $resources = $this->uriParser->parse($httpRequest);
        if ($resources === null) {
            return $this->createResourceNotFoundRoute();
        }

        $resourceType = $this->getMainResource($resources);
        if ($httpRequest->getMethod() === Request::METHOD_OPTIONS) {
            return $this->createOptionsRoute($resourceType);
        }

        $route = $this->resourceRouteLoader->load(
            $resourceType[RequestConstantsInterface::ATTRIBUTE_TYPE],
            $resources,
            $httpRequest
        );

        if (!$route) {
            return $this->createResourceNotFoundRoute();
        }

        if (!$this->isParentValid($route, $resources)) {
            return $this->createResourceNotFoundRoute();
        }

        if ($httpRequest->getMethod() === Request::METHOD_POST && isset($resourceType['id'])) {
            return $this->createResourceNotFoundRoute();
        }

        return $this->buildRouteParameters($route, $resourceType, $resources);
    }

    /**
     * @param string $module
     * @param string $controller
     * @param string $action
     *
     * @return array
     */
    protected function createRoute(string $module, string $controller, string $action): array
    {
        $routerResolver = new RouteNameResolver($module, $controller, $action);

        $service = (new ControllerServiceBuilder())->createServiceForController(
            $this->application,
            new BundleControllerAction($module, $controller, $action),
            new ControllerResolver(),
            $routerResolver
        );

        return [
            '_controller' => $service,
            '_route' => $routerResolver->resolve(),
        ];
    }

    /**
     * @return array
     */
    protected function createResourceNotFoundRoute(): array
    {
        return $this->createRoute('GlueApplication', 'ErrorRest', 'resource-not-found');
    }

    /**
     * @param array $resources
     *
     * @return array
     */
    protected function getMainResource(array $resources): array
    {
        return $resources[count($resources) - 1];
    }

    /**
     * @param array $resources
     * @param array $currentResource
     *
     * @return bool
     */
    protected function isValidPath(array $resources, array $currentResource): bool
    {
        foreach ($resources as $resourceNr => $resource) {
            if ($resource[RequestConstantsInterface::ATTRIBUTE_TYPE] !== $currentResource[RequestConstantsInterface::ATTRIBUTE_PARENT_RESOURCE]) {
                continue;
            }

            return $this->isValidChildParent($resources, $currentResource, $resourceNr);
        }

        return false;
    }

    /**
     * @param array $resources
     * @param array $currentResource
     * @param int $resourceNr
     *
     * @return bool
     */
    protected function isValidChildParent(array $resources, array $currentResource, int $resourceNr): bool
    {
        $nextResource = isset($resources[$resourceNr + 1]) ? $resources[$resourceNr + 1] : null;
        if (!$nextResource) {
            return false;
        }

        if ($nextResource[RequestConstantsInterface::ATTRIBUTE_TYPE] === $currentResource[RequestConstantsInterface::ATTRIBUTE_TYPE]) {
            return true;
        }

        return false;
    }

    /**
     * @param array $route
     * @param array $resource
     * @param array $resources
     *
     * @return array
     */
    protected function buildRouteParameters(array $route, array $resource, array $resources): array
    {
        $routeParams = $this->createRoute(
            $route[RequestConstantsInterface::ATTRIBUTE_MODULE],
            $route[RequestConstantsInterface::ATTRIBUTE_CONTROLLER],
            $route[RequestConstantsInterface::ATTRIBUTE_CONFIGURATION]['action']
        );

        $routeParams = array_merge(
            $routeParams,
            $resource,
            [
                RequestConstantsInterface::ATTRIBUTE_ALL_RESOURCES => $resources,
                RequestConstantsInterface::ATTRIBUTE_RESOURCE_FQCN => $route[RequestConstantsInterface::ATTRIBUTE_RESOURCE_FQCN],
                RequestConstantsInterface::ATTRIBUTE_CONTEXT => $route[RequestConstantsInterface::ATTRIBUTE_CONFIGURATION]['context'],
                RequestConstantsInterface::ATTRIBUTE_IS_PROTECTED => $route[RequestConstantsInterface::ATTRIBUTE_CONFIGURATION]['is_protected'],
            ]
        );
        return $routeParams;
    }

    /**
     * @param array $resourceType
     *
     * @return array
     */
    protected function createOptionsRoute(array $resourceType): array
    {
        $route = $this->createRoute('GlueApplication', 'Options', 'resource-options');
        $route[RequestConstantsInterface::ATTRIBUTE_TYPE] = $resourceType[RequestConstantsInterface::ATTRIBUTE_TYPE];

        return $route;
    }

    /**
     * @param array $route
     * @param array $resources
     *
     * @return bool
     */
    protected function isParentValid(array $route, array $resources): bool
    {
        if (isset($route[RequestConstantsInterface::ATTRIBUTE_PARENT_RESOURCE])
            && $route[RequestConstantsInterface::ATTRIBUTE_PARENT_RESOURCE] !== $resources[0][RequestConstantsInterface::ATTRIBUTE_TYPE]) {
            return false;
        }

        if (!isset($route[RequestConstantsInterface::ATTRIBUTE_PARENT_RESOURCE])
            && $route[RequestConstantsInterface::ATTRIBUTE_TYPE] !== $resources[0][RequestConstantsInterface::ATTRIBUTE_TYPE]) {
            return false;
        }

        return !isset($route[RequestConstantsInterface::ATTRIBUTE_PARENT_RESOURCE]) || $this->isValidPath($resources, $route);
    }
}
