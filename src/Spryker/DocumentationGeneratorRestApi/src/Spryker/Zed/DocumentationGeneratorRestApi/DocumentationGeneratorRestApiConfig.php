<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\DocumentationGeneratorRestApi;

use Spryker\Shared\GlueApplication\GlueApplicationConstants;
use Spryker\Shared\Kernel\KernelConstants;
use Spryker\Zed\Kernel\AbstractBundleConfig;

class DocumentationGeneratorRestApiConfig extends AbstractBundleConfig
{
    public const GENERATED_FILE_TARGET_DIRECTORY = APPLICATION_SOURCE_DIR . '/Generated/Glue/Specification/';
    public const GENERATED_FILE_NAME_PREFIX = 'spryker_rest_api';

    public const REST_API_DOCUMENTATION_INFO_VERSION = '1.0.0';
    public const REST_API_DOCUMENTATION_INFO_TITLE = 'Spryker API';
    public const REST_API_DOCUMENTATION_INFO_LICENSE_NAME = 'MIT';

    protected const APPLICATION_PROJECT_ANNOTATION_SOURCE_DIRECTORY_PATTERN = '/Glue/%1$s/Controller/';
    protected const APPLICATION_CORE_ANNOTATION_SOURCE_DIRECTORY_PATTERN = '/*/*/src/*/Glue/%1$s/Controller/';

    /**
     * @return string
     */
    public function getGeneratedFileTargetDirectory(): string
    {
        return static::GENERATED_FILE_TARGET_DIRECTORY;
    }

    /**
     * @return string
     */
    public function getGeneratedFileNamePrefix(): string
    {
        return static::GENERATED_FILE_NAME_PREFIX;
    }

    /**
     * @return string
     */
    public function getApiDocumentationVersionInfo(): string
    {
        return static::REST_API_DOCUMENTATION_INFO_VERSION;
    }

    /**
     * @return string
     */
    public function getApiDocumentationTitleInfo(): string
    {
        return static::REST_API_DOCUMENTATION_INFO_TITLE;
    }

    /**
     * @return string
     */
    public function getApiDocumentationLicenceNameInfo(): string
    {
        return static::REST_API_DOCUMENTATION_INFO_LICENSE_NAME;
    }

    /**
     * @return string
     */
    public function getRestApplicationDomain(): string
    {
        return $this->get(GlueApplicationConstants::GLUE_APPLICATION_DOMAIN);
    }

    /**
     * @return array
     */
    public function getAnnotationSourceDirectories(): array
    {
        return array_merge(
            $this->getCoreAnnotationSourceDirectoryPatterns(),
            $this->getProjectAnnotationSourceDirectoryPatterns()
        );
    }

    /**
     * @return array
     */
    protected function getCoreAnnotationSourceDirectoryPatterns(): array
    {
        return [
            APPLICATION_VENDOR_DIR . static::APPLICATION_CORE_ANNOTATION_SOURCE_DIRECTORY_PATTERN,
        ];
    }

    /**
     * @return array
     */
    protected function getProjectAnnotationSourceDirectoryPatterns(): array
    {
        return [
            APPLICATION_SOURCE_DIR . '/' . $this->get(KernelConstants::PROJECT_NAMESPACE) . static::APPLICATION_PROJECT_ANNOTATION_SOURCE_DIRECTORY_PATTERN,
        ];
    }
}
