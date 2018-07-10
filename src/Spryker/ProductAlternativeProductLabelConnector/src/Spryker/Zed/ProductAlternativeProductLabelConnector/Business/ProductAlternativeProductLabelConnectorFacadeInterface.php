<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductAlternativeProductLabelConnector\Business;

interface ProductAlternativeProductLabelConnectorFacadeInterface
{
    /**
     * Specification:
     *  - Installs label for alternative products.
     *
     * @api
     *
     * @return void
     */
    public function installProductAlternativeProductLabelConnector(): void;

    /**
     * Specification:
     *  - Adds or removes label "Alternatives available" if applicable.
     *
     * @api
     *
     * @param int $idProduct
     *
     * @return void
     */
    public function updateAbstractProductWithAlternativesAvailableLabel(int $idProduct): void;

    /**
     * Specification:
     *  - Removes label "Alternatives available" if applicable.
     *
     * @api
     *
     * @param int $idProduct
     *
     * @return void
     */
    public function removeProductAbstractRelationsForLabel(int $idProduct): void;

    /**
     * Specification:
     * - Returns a list of Product Label - Product Abstract relation to assign and deassign.
     * - The relation changes are based on presence of alternatives.
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\ProductLabelProductAbstractRelationsTransfer[]
     */
    public function findProductLabelProductAbstractRelationChanges(): array;
}
