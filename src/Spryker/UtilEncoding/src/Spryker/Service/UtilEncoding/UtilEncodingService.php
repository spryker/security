<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\UtilEncoding;

use Spryker\Service\Kernel\AbstractService;

/**
 * @method \Spryker\Service\UtilEncoding\UtilEncodingServiceFactory getFactory()
 */
class UtilEncodingService extends AbstractService implements UtilEncodingServiceInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param mixed $value
     * @param int|null $options
     * @param int|null $depth
     *
     * @return string|null
     */
    public function encodeJson($value, $options = null, $depth = null)
    {
        return $this->getFactory()
            ->createJsonEncoder()
            ->encode($value, $options, $depth);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $jsonValue
     * @param bool $assoc
     * @param int|null $depth
     * @param int|null $options
     *
     * @return mixed|null
     */
    public function decodeJson($jsonValue, $assoc = false, $depth = null, $options = null)
    {
        return $this->getFactory()
            ->createJsonEncoder()
            ->decode($jsonValue, $assoc, $depth, $options);
    }
}
