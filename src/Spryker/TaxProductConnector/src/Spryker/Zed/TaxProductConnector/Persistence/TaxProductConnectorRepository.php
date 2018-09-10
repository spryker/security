<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\TaxProductConnector\Persistence;

use Generated\Shared\Transfer\TaxRateSetTransfer;
use Spryker\Zed\Kernel\Persistence\AbstractRepository;

/**
 * @method \Spryker\Zed\TaxProductConnector\Persistence\TaxProductConnectorPersistenceFactory getFactory()
 */
class TaxProductConnectorRepository extends AbstractRepository implements TaxProductConnectorRepositoryInterface
{
    /**
     * @param string $productAbstractSku
     *
     * @return \Generated\Shared\Transfer\TaxRateSetTransfer|null
     */
    public function findTaxSetByProductAbstractSku(string $productAbstractSku): ?TaxRateSetTransfer
    {
        $taxSet = $this->getFactory()->createTaxSetQuery()
            ->useSpyProductAbstractQuery()
                ->filterBySku($productAbstractSku)
            ->endUse()
            ->findOne();

        if (!$taxSet) {
            return null;
        }

        return $this->getFactory()
            ->createTaxSetMapper()
            ->mapTaxSetEntityToTaxRateSetTransfer($taxSet);
    }
}
