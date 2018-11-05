<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\DocumentationGeneratorRestApi\Business\Renderer\Component;

/**
 * Specification:
 *  - This component describes a security scheme that can be used by the operations.
 *  - This component covers Security Scheme Object in OpenAPI specification format (see https://swagger.io/specification/#securitySchemeObject).
 */
class SecuritySchemeSpecificationComponent extends AbstractSpecificationComponent
{
    protected const KEY_TYPE = 'type';
    protected const KEY_SCHEME = 'scheme';
    protected const KEY_IN = 'in';

    /**
     * @var string
     */
    protected $name;

    /**
     * @var string
     */
    protected $type;

    /**
     * @var string
     */
    protected $scheme;

    /**
     * @return array
     */
    public function toArray(): array
    {
        $securitySchemaData[$this->name][static::KEY_TYPE] = $this->type;
        $securitySchemaData[$this->name][static::KEY_SCHEME] = $this->scheme;

        return $securitySchemaData;
    }

    /**
     * @return array
     */
    public function getRequiredProperties(): array
    {
        return [
            $this->name,
            $this->type,
            $this->scheme,
        ];
    }

    /**
     * @param string $name
     *
     * @return void
     */
    public function setName(string $name): void
    {
        $this->name = $name;
    }

    /**
     * @param string $type
     *
     * @return void
     */
    public function setType(string $type): void
    {
        $this->type = $type;
    }

    /**
     * @param string $scheme
     *
     * @return void
     */
    public function setScheme(string $scheme): void
    {
        $this->scheme = $scheme;
    }
}
