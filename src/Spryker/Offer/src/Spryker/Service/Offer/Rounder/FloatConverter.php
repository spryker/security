<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\Offer\Rounder;

use Spryker\Service\Offer\OfferConfig;

class FloatConverter implements FloatConverterInterface
{
    /**
     * @var \Spryker\Service\Offer\OfferConfig
     */
    protected $config;

    /**
     * @param \Spryker\Service\Offer\OfferConfig $config
     */
    public function __construct(OfferConfig $config)
    {
        $this->config = $config;
    }

    /**
     * @param float $value
     *
     * @return int
     */
    public function convert(float $value): int
    {
        return (int)round($value, $this->config->getRoundPrecision(), $this->config->getRoundMode());
    }
}
