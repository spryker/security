<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\RestRequestValidator\Processor\Validator\Configuration;

use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Spryker\Glue\RestRequestValidator\Business\Exception\CacheFileNotFound;
use Spryker\Glue\RestRequestValidator\Dependency\Client\RestRequestValidatorToStoreClientInterface;
use Spryker\Glue\RestRequestValidator\Dependency\External\RestRequestValidatorToFilesystemAdapterInterface;
use Spryker\Glue\RestRequestValidator\Dependency\External\RestRequestValidatorToYamlAdapterInterface;
use Spryker\Glue\RestRequestValidator\RestRequestValidatorConfig;
use function sprintf;

class RestRequestValidatorConfigReader implements RestRequestValidatorConfigReaderInterface
{
    /**
     * @var \Spryker\Glue\RestRequestValidator\Dependency\External\RestRequestValidatorToFilesystemAdapterInterface
     */
    protected $filesystem;

    /**
     * @var \Spryker\Glue\RestRequestValidator\Dependency\External\RestRequestValidatorToYamlAdapterInterface
     */
    protected $yaml;

    /**
     * @var \Spryker\Glue\RestRequestValidator\Dependency\Client\RestRequestValidatorToStoreClientInterface
     */
    protected $storeClient;

    /**
     * @var \Spryker\Glue\RestRequestValidator\RestRequestValidatorConfig
     */
    protected $config;

    /**
     * @param \Spryker\Glue\RestRequestValidator\Dependency\External\RestRequestValidatorToFilesystemAdapterInterface $filesystem
     * @param \Spryker\Glue\RestRequestValidator\Dependency\External\RestRequestValidatorToYamlAdapterInterface $yaml
     * @param \Spryker\Glue\RestRequestValidator\Dependency\Client\RestRequestValidatorToStoreClientInterface $storeClient
     * @param \Spryker\Glue\RestRequestValidator\RestRequestValidatorConfig $config
     */
    public function __construct(
        RestRequestValidatorToFilesystemAdapterInterface $filesystem,
        RestRequestValidatorToYamlAdapterInterface $yaml,
        RestRequestValidatorToStoreClientInterface $storeClient,
        RestRequestValidatorConfig $config
    ) {
        $this->filesystem = $filesystem;
        $this->yaml = $yaml;
        $this->storeClient = $storeClient;
        $this->config = $config;
    }

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @throws \Spryker\Glue\RestRequestValidator\Business\Exception\CacheFileNotFound
     *
     * @return array
     */
    public function getValidationConfiguration(RestRequestInterface $restRequest): array
    {
        if (!$this->filesystem->exists($this->getValidationConfigPath())) {
            throw new CacheFileNotFound('Validation cache is enabled, but there is no cache file.');
        }

        $configuration = $this->yaml->parseFile($this->getValidationConfigPath());

        $resourceType = $restRequest->getResource()->getType();
        $requestMethod = strtolower($restRequest->getMetadata()->getMethod());

        if (empty($configuration[$resourceType][$requestMethod])) {
            return [];
        }

        return $configuration[$resourceType][$requestMethod];
    }

    /**
     * @return string
     */
    protected function getValidationConfigPath(): string
    {
        return sprintf($this->config->getValidationCacheFilenamePattern(), $this->storeClient->getCurrentStore()->getName());
    }
}
