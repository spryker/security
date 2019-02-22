<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\DiscountPromotion\Communication\Plugin\Discount;

use Generated\Shared\Transfer\DiscountConfiguratorTransfer;
use Generated\Shared\Transfer\DiscountPromotionTransfer;
use Spryker\Zed\Discount\Dependency\Plugin\DiscountPostUpdatePluginInterface;

/**
 * @method \Spryker\Zed\DiscountPromotion\Business\DiscountPromotionFacadeInterface getFacade()
 * @method \Spryker\Zed\DiscountPromotion\Communication\DiscountPromotionCommunicationFactory getFactory()
 */
class DiscountPromotionPostUpdatePlugin extends BaseDiscountPromotionSaverPlugin implements DiscountPostUpdatePluginInterface
{
    /**
     * {@inheritdoc}
     *  - Check if given discount CollectorStrategyType is set to "promotion"
     *    and if so, updates Promotion for Discount.
     *  - If not, removes Promotion from Discount.
     *  - Sets updated DiscountPromotion to DiscountCalculator of DiscountConfigurator.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\DiscountConfiguratorTransfer $discountConfiguratorTransfer
     *
     * @return \Generated\Shared\Transfer\DiscountConfiguratorTransfer $discountConfiguratorTransfer
     */
    public function postUpdate(DiscountConfiguratorTransfer $discountConfiguratorTransfer)
    {
        $discountPromotionTransfer = $this->getDiscountPromotionTransfer($discountConfiguratorTransfer);

        if (!$this->isDiscountWithPromotion($discountConfiguratorTransfer)) {
            $this->getFacade()->removePromotionFromDiscount($discountPromotionTransfer);
            $discountConfiguratorTransfer->getDiscountCalculator()->setDiscountPromotion(new DiscountPromotionTransfer());

            return $discountConfiguratorTransfer;
        }

        $discountPromotionTransfer = $this->getFacade()->updatePromotionDiscount($discountPromotionTransfer);
        $discountConfiguratorTransfer->getDiscountCalculator()->setDiscountPromotion($discountPromotionTransfer);

        return $discountConfiguratorTransfer;
    }
}
