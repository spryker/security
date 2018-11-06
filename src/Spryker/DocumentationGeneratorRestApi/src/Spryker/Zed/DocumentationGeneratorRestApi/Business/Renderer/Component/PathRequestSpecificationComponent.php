<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\DocumentationGeneratorRestApi\Business\Renderer\Component;

use Generated\Shared\Transfer\OpenApiSpecificationPathRequestComponentTransfer;

/**
 * Specification:
 *  - This component describes a single request body.
 *  - It covers Request Body Object in OpenAPI specification format (see https://swagger.io/specification/#requestBodyObject)
 */
class PathRequestSpecificationComponent extends AbstractSpecificationComponent implements PathRequestSpecificationComponentInterface
{
    protected const KEY_APPLICATION_JSON = 'application/json';
    protected const KEY_CONTENT = 'content';
    protected const KEY_DESCRIPTION = 'description';
    protected const KEY_REF = '$ref';
    protected const KEY_REQUIRED = 'required';
    protected const KEY_SCHEMA = 'schema';

    /**
     * @var \Generated\Shared\Transfer\OpenApiSpecificationPathRequestComponentTransfer $pathRequestComponentTransfer
     */
    protected $pathRequestComponentTransfer;

    /**
     * @param \Generated\Shared\Transfer\OpenApiSpecificationPathRequestComponentTransfer $pathRequestComponentTransfer
     *
     * @return void
     */
    public function setPathRequestComponentTransfer(OpenApiSpecificationPathRequestComponentTransfer $pathRequestComponentTransfer): void
    {
        $this->pathRequestComponentTransfer = $pathRequestComponentTransfer;
    }

    /**
     * @return array
     */
    public function getSpecificationComponentData(): array
    {
        $result = [];

        $result[static::KEY_DESCRIPTION] = $this->pathRequestComponentTransfer->getDescription();
        $result[static::KEY_REQUIRED] = $this->pathRequestComponentTransfer->getRequired();
        if ($this->pathRequestComponentTransfer->getJsonSchemaRef()) {
            $result[static::KEY_CONTENT][static::KEY_APPLICATION_JSON][static::KEY_SCHEMA][static::KEY_REF] = $this->pathRequestComponentTransfer->getJsonSchemaRef();
        }

        return $result;
    }

    /**
     * @return array
     */
    protected function getRequiredProperties(): array
    {
        return [
            $this->pathRequestComponentTransfer->getDescription(),
            $this->pathRequestComponentTransfer->getRequired(),
            $this->pathRequestComponentTransfer->getJsonSchemaRef(),
        ];
    }
}
