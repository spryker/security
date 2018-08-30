<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductManagement\Communication\Form\Validator\Constraints;

use ArrayObject;
use Spryker\Zed\ProductManagement\Communication\Form\Product\Price\ProductMoneyCollectionType;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

class ProductMoneyNotBlankValidator extends ConstraintValidator
{
    /**
     * @param mixed $value
     * @param \Spryker\Zed\ProductManagement\Communication\Form\Validator\Constraints\SkuUnique|\Symfony\Component\Validator\Constraint $constraint
     *
     * @return void
     */
    public function validate($value, Constraint $constraint)
    {
        if ($value === null || $value === '') {
            return;
        }

        $this->validateProductMoneyNotBlank($value, $constraint);
    }

    /**
     * @param mixed $value
     * @param \Spryker\Zed\ProductManagement\Communication\Form\Validator\Constraints\ProductMoneyNotBlank $constraint
     *
     * @return void
     */
    protected function validateProductMoneyNotBlank($value, ProductMoneyNotBlank $constraint)
    {
        foreach ($this->getGrouppedPricesArray($value) as $priceGroup) {
            if ($this->validatePriceGroup($priceGroup)) {
                return;
            }
        }

        $this->context->buildViolation($constraint->message)->addViolation();
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductTransfer[] $priceGroup
     *
     * @return bool
     */
    protected function validatePriceGroup(array $priceGroup)
    {
        foreach ($priceGroup as $priceProductTransfer) {
            $moneyValueTransfer = $priceProductTransfer->getMoneyValue();

            if ($moneyValueTransfer->getGrossAmount() === null || $moneyValueTransfer->getNetAmount() === null) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\PriceProductTransfer[] $productPrices
     *
     * @return array
     */
    protected function getGrouppedPricesArray(ArrayObject $productPrices)
    {
        $grouppedPrices = [];

        foreach ($productPrices as $compositeKey => $priceProductTransfer) {
            $grouppedPrices[$this->getGroupKeyFromCompositePriceKey($compositeKey)][] = $priceProductTransfer;
        }

        return $grouppedPrices;
    }

    /**
     * @param string $compositeKey
     *
     * @return string
     */
    protected function getGroupKeyFromCompositePriceKey(string $compositeKey)
    {
        $keyPartials = explode(ProductMoneyCollectionType::PRICE_DELIMITER, $compositeKey);

        return $keyPartials[0] . ProductMoneyCollectionType::PRICE_DELIMITER . $keyPartials[1];
    }
}
