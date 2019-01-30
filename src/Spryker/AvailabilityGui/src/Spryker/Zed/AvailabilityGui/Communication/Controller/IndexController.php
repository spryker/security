<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\AvailabilityGui\Communication\Controller;

use Generated\Shared\Transfer\AvailabilityStockTransfer;
use Generated\Shared\Transfer\StockProductTransfer;
use Spryker\Zed\AvailabilityGui\Communication\Table\AvailabilityAbstractTable;
use Spryker\Zed\AvailabilityGui\Communication\Table\AvailabilityTable;
use Spryker\Zed\AvailabilityGui\Communication\Table\BundledProductAvailabilityTable;
use Spryker\Zed\Kernel\Communication\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\AvailabilityGui\Communication\AvailabilityGuiCommunicationFactory getFactory()
 */
class IndexController extends AbstractController
{
    public const URL_PARAM_ID_STORE = 'id-store';

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array
     */
    public function indexAction(Request $request)
    {
        $idStore = $this->extractStoreId($request);

        $availabilityAbstractTable = $this->getAvailabilityAbstractTable($idStore);

        $storeTransfer = $this->getFactory()->getStoreFacade()->getCurrentStore();
        $stores = $this->getFactory()->getStoreFacade()->getStoresWithSharedPersistence($storeTransfer);
        $stores[] = $storeTransfer;

        return [
            'indexTable' => $availabilityAbstractTable->render(),
            'stores' => $stores,
            'idStore' => $idStore,
        ];
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array
     */
    public function viewAction(Request $request)
    {
        $idProductAbstract = $this->castId($request->query->getInt(AvailabilityAbstractTable::URL_PARAM_ID_PRODUCT_ABSTRACT));

        $idStore = $this->extractStoreId($request);

        $availabilityTable = $this->getAvailabilityTable($idProductAbstract, $idStore);

        $localeTransfer = $this->getCurrentLocaleTransfer();

        $productAbstractAvailabilityTransfer = $this->getFactory()
            ->getAvailabilityFacade()
            ->findProductAbstractAvailability($idProductAbstract, $localeTransfer->getIdLocale(), $idStore);

        $bundledProductAvailabilityTable = $this->getBundledProductAvailabilityTable($idStore);

        $storeTransfer = $this->getFactory()->getStoreFacade()->getCurrentStore();
        $stores = $this->getFactory()->getStoreFacade()->getStoresWithSharedPersistence($storeTransfer);
        $stores[] = $storeTransfer;

        return [
            'productAbstractAvailability' => $productAbstractAvailabilityTransfer,
            'indexTable' => $availabilityTable->render(),
            'bundledProductAvailabilityTable' => $bundledProductAvailabilityTable->render(),
            'stores' => $stores,
            'idStore' => $idStore,
            'idProduct' => $idProductAbstract,
        ];
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array
     */
    public function editAction(Request $request)
    {
        $idProduct = $this->castId($request->query->getInt(AvailabilityTable::URL_PARAM_ID_PRODUCT));
        $idStore = $this->castId($request->query->getInt(AvailabilityTable::URL_PARAM_ID_STORE));
        $idProductAbstract = $this->castId($request->query->getInt(AvailabilityTable::URL_PARAM_ID_PRODUCT_ABSTRACT));
        $sku = $request->query->get(AvailabilityTable::URL_PARAM_SKU);

        $storeTransfer = $this->getFactory()->getStoreFacade()->getStoreById($idStore);

        $availabilityStockForm = $this->getFactory()->createAvailabilityStockForm($idProduct, $sku, $storeTransfer);
        $availabilityStockForm->handleRequest($request);

        if ($availabilityStockForm->isSubmitted() && $availabilityStockForm->isValid()) {
            $data = $availabilityStockForm->getData();
            if ($this->saveAvailabilityStock($data)) {
                $this->addSuccessMessage('Stock successfully updated');
            } else {
                $this->addErrorMessage('Failed to update stock, please enter stock amount or select "never out of stock"');
            }
        }

        return [
            'form' => $availabilityStockForm->createView(),
            'idProductAbstract' => $idProductAbstract,
        ];
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Symfony\Component\HttpFoundation\JsonResponse
     */
    public function availabilityAbstractTableAction(Request $request)
    {
        $idStore = $this->extractStoreId($request);

        $availabilityAbstractTable = $this->getAvailabilityAbstractTable($idStore);

        return $this->jsonResponse(
            $availabilityAbstractTable->fetchData()
        );
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Symfony\Component\HttpFoundation\JsonResponse
     */
    public function availabilityTableAction(Request $request)
    {
        $idProductAbstract = $this->castId($request->query->getInt(AvailabilityAbstractTable::URL_PARAM_ID_PRODUCT_ABSTRACT));
        $idStore = $this->castId($request->query->getInt(static::URL_PARAM_ID_STORE));
        $availabilityTable = $this->getAvailabilityTable($idProductAbstract, $idStore);

        return $this->jsonResponse(
            $availabilityTable->fetchData()
        );
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Symfony\Component\HttpFoundation\JsonResponse
     */
    public function bundledProductAvailabilityTableAction(Request $request)
    {
        $idBundleProduct = $request->query->getInt(BundledProductAvailabilityTable::URL_PARAM_ID_PRODUCT_BUNDLE);
        $idStore = $this->castId($request->query->getInt(BundledProductAvailabilityTable::URL_PARAM_ID_STORE));

        if (!$idBundleProduct) {
            return $this->jsonResponse([]);
        }

        $idBundleProduct = $this->castId($idBundleProduct);
        $idBundleProductAbstract = $this->castId($request->query->getInt(BundledProductAvailabilityTable::URL_PARAM_BUNDLE_ID_PRODUCT_ABSTRACT));
        $bundledProductAvailabilityTable = $this->getBundledProductAvailabilityTable($idStore, $idBundleProduct, $idBundleProductAbstract);

        return $this->jsonResponse(
            $bundledProductAvailabilityTable->fetchData()
        );
    }

    /**
     * @param int $idStore
     *
     * @return \Spryker\Zed\AvailabilityGui\Communication\Table\AvailabilityAbstractTable
     */
    protected function getAvailabilityAbstractTable($idStore)
    {
        $localeTransfer = $this->getCurrentLocaleTransfer();

        return $this->getFactory()->createAvailabilityAbstractTable($localeTransfer->getIdLocale(), $idStore);
    }

    /**
     * @return \Generated\Shared\Transfer\LocaleTransfer
     */
    protected function getCurrentLocaleTransfer()
    {
        $localeFacade = $this->getFactory()->getLocalFacade();

        return $localeFacade->getCurrentLocale();
    }

    /**
     * @param int $idProductAbstract
     * @param int $idStore
     *
     * @return \Spryker\Zed\AvailabilityGui\Communication\Table\AvailabilityTable
     */
    protected function getAvailabilityTable($idProductAbstract, $idStore)
    {
        $localeTransfer = $this->getCurrentLocaleTransfer();

        if (!$idStore) {
            $idStore = $this->getFactory()->getStoreFacade()->getCurrentStore()->getIdStore();
        }

        return $this->getFactory()->createAvailabilityTable(
            $idProductAbstract,
            $localeTransfer->getIdLocale(),
            $idStore
        );
    }

    /**
     * @param int $idStore
     * @param int|null $idProductBundle
     * @param int|null $idBundleProductAbstract
     *
     * @return \Spryker\Zed\AvailabilityGui\Communication\Table\BundledProductAvailabilityTable
     */
    protected function getBundledProductAvailabilityTable($idStore, $idProductBundle = null, $idBundleProductAbstract = null)
    {
        $localeTransfer = $this->getCurrentLocaleTransfer();

        return $this->getFactory()
            ->createBundledProductAvailabilityTable(
                $localeTransfer->getIdLocale(),
                $idStore,
                $idProductBundle,
                $idBundleProductAbstract
            );
    }

    /**
     * @param \Generated\Shared\Transfer\AvailabilityStockTransfer $availabilityStockTransfer
     *
     * @return bool
     */
    protected function saveAvailabilityStock(AvailabilityStockTransfer $availabilityStockTransfer)
    {
        $isAnyItemsUpdated = false;
        foreach ($availabilityStockTransfer->getStocks() as $stockProductTransfer) {
            if ($stockProductTransfer->getIdStockProduct() !== null) {
                if ($this->getFactory()->getStockFacade()->updateStockProduct($stockProductTransfer) > 0) {
                    $isAnyItemsUpdated = true;
                }
            } elseif ($this->isStockProductTransferValid($stockProductTransfer)) {
                $stockProductTransfer->setSku($availabilityStockTransfer->getSku());
                if ($this->getFactory()->getStockFacade()->createStockProduct($stockProductTransfer) > 0) {
                    $isAnyItemsUpdated = true;
                }
            }
        }

        return $isAnyItemsUpdated;
    }

    /**
     * @param \Generated\Shared\Transfer\StockProductTransfer $stockProductTransfer
     *
     * @return bool
     */
    protected function isStockProductTransferValid(StockProductTransfer $stockProductTransfer)
    {
        $floatCalculator = $this->getFactory()->createFloatCalculator();
        $stockProductQuantityIsZero = (bool)$floatCalculator->compare($stockProductTransfer->getQuantity(), 0.0);

        return $stockProductTransfer->getIdStockProduct() === null && !$stockProductQuantityIsZero || $stockProductTransfer->getIsNeverOutOfStock();
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return int|mixed
     */
    protected function extractStoreId(Request $request)
    {
        $idStore = $request->query->getInt(static::URL_PARAM_ID_STORE);
        if (!$idStore) {
            $idStore = $this->getFactory()->getStoreFacade()->getCurrentStore()->getIdStore();
        }
        return $this->castId($idStore);
    }
}
