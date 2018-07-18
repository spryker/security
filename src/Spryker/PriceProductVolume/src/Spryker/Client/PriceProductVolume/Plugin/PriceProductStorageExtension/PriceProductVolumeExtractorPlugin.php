<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\PriceProductVolume\Plugin\PriceProductStorageExtension;

use Spryker\Client\Kernel\AbstractPlugin;
use Spryker\Client\PriceProductStorageExtension\Dependency\Plugin\PriceProductStoragePricesExtractorPluginInterface;

/**
 * @method \Spryker\Client\PriceProductVolume\PriceProductVolumeFactory getFactory()
 */
class PriceProductVolumeExtractorPlugin extends AbstractPlugin implements PriceProductStoragePricesExtractorPluginInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\PriceProductTransfer[] $priceProductTransfers
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function extractProductPricesForProductAbstract(array $priceProductTransfers): array
    {
        return $this->getFactory()
            ->createVolumePriceExtractor()
            ->extractProductPricesForProductAbstract($priceProductTransfers);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProductConcrete
     * @param \Generated\Shared\Transfer\PriceProductTransfer[] $priceProductTransfers
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function extractProductPricesForProductConcrete(int $idProductConcrete, array $priceProductTransfers): array
    {
        return $this->getFactory()
            ->createVolumePriceExtractor()
            ->extractProductPricesForProductConcrete($idProductConcrete, $priceProductTransfers);
    }
}
