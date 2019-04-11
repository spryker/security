<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsBlockProductConnector\Communication\DataProvider;

use Generated\Shared\Transfer\CmsBlockTransfer;
use Spryker\Zed\CmsBlockProductConnector\Communication\Form\CmsBlockProductAbstractType;
use Spryker\Zed\CmsBlockProductConnector\Communication\Formatter\ProductCollectionFormatterInterface;
use Spryker\Zed\CmsBlockProductConnector\Dependency\Facade\CmsBlockProductConnectorToLocaleInterface;
use Spryker\Zed\CmsBlockProductConnector\Persistence\CmsBlockProductConnectorRepositoryInterface;

class CmsBlockProductDataProvider
{
    public const OPTION_PRODUCT_AUTOCOMPLETE_URL = '/cms-block-product-connector/product-autocomplete/';

    /**
     * @var \Spryker\Zed\CmsBlockProductConnector\Dependency\Facade\CmsBlockProductConnectorToLocaleInterface
     */
    protected $localeFacade;

    /**
     * @var \Spryker\Zed\CmsBlockProductConnector\Persistence\CmsBlockProductConnectorRepositoryInterface
     */
    protected $cmsBlockProductConnectorRepository;

    /**
     * @var \Spryker\Zed\CmsBlockProductConnector\Communication\Formatter\ProductCollectionFormatterInterface
     */
    protected $productCollectionFormatter;

    /**
     * @param \Spryker\Zed\CmsBlockProductConnector\Dependency\Facade\CmsBlockProductConnectorToLocaleInterface $localeFacade
     * @param \Spryker\Zed\CmsBlockProductConnector\Persistence\CmsBlockProductConnectorRepositoryInterface $repository
     * @param \Spryker\Zed\CmsBlockProductConnector\Communication\Formatter\ProductCollectionFormatterInterface $productCollectionFormatter
     */
    public function __construct(
        CmsBlockProductConnectorToLocaleInterface $localeFacade,
        CmsBlockProductConnectorRepositoryInterface $repository,
        ProductCollectionFormatterInterface $productCollectionFormatter
    ) {
        $this->localeFacade = $localeFacade;
        $this->cmsBlockProductConnectorRepository = $repository;
        $this->productCollectionFormatter = $productCollectionFormatter;
    }

    /**
     * @param \Generated\Shared\Transfer\CmsBlockTransfer $cmsBlockTransfer
     *
     * @return array
     */
    public function getOptions(CmsBlockTransfer $cmsBlockTransfer)
    {
        return [
            'data_class' => CmsBlockTransfer::class,
            CmsBlockProductAbstractType::OPTION_ASSIGNED_PRODUCT_ABSTRACTS => $this->getAssignedProductAbstracts($cmsBlockTransfer),
            CmsBlockProductAbstractType::OPTION_PRODUCT_AUTOCOMPLETE_URL => static::OPTION_PRODUCT_AUTOCOMPLETE_URL,
        ];
    }

    /**
     * @param \Generated\Shared\Transfer\CmsBlockTransfer $cmsBlockTransfer
     *
     * @return \Generated\Shared\Transfer\CmsBlockTransfer
     */
    public function getData(CmsBlockTransfer $cmsBlockTransfer)
    {
        $idProductAbstracts = [];

        if ($cmsBlockTransfer->getIdCmsBlock()) {
            $idProductAbstracts = $this->cmsBlockProductConnectorRepository->getAssignedProductAbstractIds($cmsBlockTransfer->getIdCmsBlock());
        }

        $cmsBlockTransfer->setIdProductAbstracts($idProductAbstracts);

        return $cmsBlockTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\CmsBlockTransfer $cmsBlockTransfer
     *
     * @return array
     */
    protected function getAssignedProductAbstracts(CmsBlockTransfer $cmsBlockTransfer): array
    {
        $productAbstractOptions = [];

        $idLocale = $this->localeFacade
            ->getCurrentLocale()
            ->getIdLocale();

        if ($cmsBlockTransfer->getIdCmsBlock() === null) {
            return $productAbstractOptions;
        }
        $productAbstractTransfers = $this->cmsBlockProductConnectorRepository->getAssignedProductAbstracts(
            $idLocale,
            $cmsBlockTransfer->getIdCmsBlock()
        );

        return $this->productCollectionFormatter->formatTransfers($productAbstractTransfers);
    }
}
