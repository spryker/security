<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationshipMinimumOrderValue\Business\Translation;

use Generated\Shared\Transfer\MerchantRelationshipMinimumOrderValueTransfer;

class MerchantRelationshipMinimumOrderValueGlossaryKeyGenerator implements MerchantRelationshipMinimumOrderValueGlossaryKeyGeneratorInterface
{
    protected const MINIMUM_ORDER_VALUE_GLOSSARY_PREFIX = 'merchant-relationship-minimum-order-value';
    protected const MINIMUM_ORDER_VALUE_GLOSSARY_MESSAGE = 'message';

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipMinimumOrderValueTransfer $merchantRelationshipMinimumOrderValueTransfer
     *
     * @return void
     */
    public function assignMessageGlossaryKey(MerchantRelationshipMinimumOrderValueTransfer $merchantRelationshipMinimumOrderValueTransfer): void
    {
        $this->assertRequired($merchantRelationshipMinimumOrderValueTransfer);

        $merchantRelationshipMinimumOrderValueTransfer->getMinimumOrderValue()->setMessageGlossaryKey(
            $this->generateMessageGlossaryKey($merchantRelationshipMinimumOrderValueTransfer)
        );
    }

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipMinimumOrderValueTransfer $merchantRelationshipMinimumOrderValueTransfer
     *
     * @return string
     */
    protected function generateMessageGlossaryKey(MerchantRelationshipMinimumOrderValueTransfer $merchantRelationshipMinimumOrderValueTransfer): string
    {
        return strtolower(implode(
            '.',
            [
                static::MINIMUM_ORDER_VALUE_GLOSSARY_PREFIX,
                $merchantRelationshipMinimumOrderValueTransfer->getMinimumOrderValue()->getMinimumOrderValueType()->getThresholdGroup(),
                $merchantRelationshipMinimumOrderValueTransfer->getStore()->getName(),
                $merchantRelationshipMinimumOrderValueTransfer->getCurrency()->getCode(),
                $merchantRelationshipMinimumOrderValueTransfer->getMerchantRelationship()->getIdMerchantRelationship(),
                static::MINIMUM_ORDER_VALUE_GLOSSARY_MESSAGE,
            ]
        ));
    }

    /**
     * @param \Spryker\Zed\MerchantRelationshipMinimumOrderValue\Business\Translation\MerchantRelationshipMinimumOrderValueTransfer $merchantRelationshipMinimumOrderValueTransfer
     *
     * @return void
     */
    protected function assertRequired(MerchantRelationshipMinimumOrderValueTransfer $merchantRelationshipMinimumOrderValueTransfer): void
    {
        $merchantRelationshipMinimumOrderValueTransfer->getMinimumOrderValue()
            ->requireMinimumOrderValueType();

        $merchantRelationshipMinimumOrderValueTransfer->getMinimumOrderValue()->getMinimumOrderValueType()
            ->requireThresholdGroup();

        $merchantRelationshipMinimumOrderValueTransfer->getStore()
            ->requireName();

        $merchantRelationshipMinimumOrderValueTransfer->getCurrency()
            ->requireCode();

        $merchantRelationshipMinimumOrderValueTransfer->getMerchantRelationship()
            ->requireIdMerchantRelationship();
    }
}
