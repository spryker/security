<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationshipProductList\Business\ProductList;

use Generated\Shared\Transfer\CompanyBusinessUnitTransfer;
use Generated\Shared\Transfer\MerchantRelationshipTransfer;
use Generated\Shared\Transfer\ProductListCollectionTransfer;
use Spryker\Zed\MerchantRelationshipProductList\Persistence\MerchantRelationshipProductListRepositoryInterface;

class ProductListReader implements ProductListReaderInterface
{
    /**
     * @var \Spryker\Zed\MerchantRelationshipProductList\Persistence\MerchantRelationshipProductListRepositoryInterface
     */
    protected $merchantRelationshipProductListRepository;

    /**
     * @param \Spryker\Zed\MerchantRelationshipProductList\Persistence\MerchantRelationshipProductListRepositoryInterface $merchantRelationshipProductListRepository
     */
    public function __construct(
        MerchantRelationshipProductListRepositoryInterface $merchantRelationshipProductListRepository
    ) {
        $this->merchantRelationshipProductListRepository = $merchantRelationshipProductListRepository;
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
     *
     * @return \Generated\Shared\Transfer\ProductListCollectionTransfer
     */
    public function getProductListCollectionByIdCompanyBusinessUnit(CompanyBusinessUnitTransfer $companyBusinessUnitTransfer): ProductListCollectionTransfer
    {
        $companyBusinessUnitTransfer->requireIdCompanyBusinessUnit();

        return $this->merchantRelationshipProductListRepository->getProductListCollectionByIdCompanyBusinessUnit($companyBusinessUnitTransfer->getIdCompanyBusinessUnit());
    }

    /**
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationshipTransfer
     *
     * @return \Generated\Shared\Transfer\ProductListCollectionTransfer
     */
    public function getProductListCollectionByIdMerchantRelationship(MerchantRelationshipTransfer $merchantRelationshipTransfer): ProductListCollectionTransfer
    {
        $merchantRelationshipTransfer->requireIdMerchantRelationship();

        return $this->merchantRelationshipProductListRepository->getProductListCollectionByIdMerchantRelationship($merchantRelationshipTransfer->getIdMerchantRelationship());
    }
}
