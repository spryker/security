<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\DiscountPromotion\Communication\Plugin\Discount;

use Spryker\Shared\DiscountPromotion\DiscountPromotionConfig;
use Spryker\Zed\Discount\Communication\Form\CalculatorForm;
use Spryker\Zed\Discount\Dependency\Plugin\Form\DiscountFormDataProviderExpanderPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;

/**
 * @method \Spryker\Zed\DiscountPromotion\Business\DiscountPromotionFacade getFacade()
 * @method \Spryker\Zed\DiscountPromotion\Communication\DiscountPromotionCommunicationFactory getFactory()
 */
class DiscountPromotionCalculationFormDataExpanderPlugin extends AbstractPlugin implements DiscountFormDataProviderExpanderPluginInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param array $options
     *
     * @return array
     */
    public function expandDataProviderOptions(array $options)
    {
        if (!isset($options[CalculatorForm::OPTION_COLLECTOR_TYPE_CHOICES])) {
            return $options;
        }

        $options[CalculatorForm::OPTION_COLLECTOR_TYPE_CHOICES][DiscountPromotionConfig::DISCOUNT_COLLECTOR_STRATEGY] = 'Discount promotion to product';

        return $options;
    }

    /**
     * @api
     *
     * {@inheritdoc}
     *
     * @param array $data
     *
     * @return array
     */
    public function expandDataProviderData(array $data)
    {
        return $data;
    }
}
