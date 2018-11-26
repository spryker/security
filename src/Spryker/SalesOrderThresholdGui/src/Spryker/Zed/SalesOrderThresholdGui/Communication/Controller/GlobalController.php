<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesOrderThresholdGui\Communication\Controller;

use Generated\Shared\Transfer\CurrencyTransfer;
use Generated\Shared\Transfer\SalesOrderThresholdTransfer;
use Generated\Shared\Transfer\SalesOrderThresholdValueTransfer;
use Generated\Shared\Transfer\StoreTransfer;
use Spryker\Zed\Kernel\Communication\Controller\AbstractController;
use Spryker\Zed\SalesOrderThresholdGui\Communication\Form\GlobalThresholdType;
use Spryker\Zed\SalesOrderThresholdGui\Communication\Form\Type\ThresholdGroup\GlobalHardThresholdType;
use Spryker\Zed\SalesOrderThresholdGui\Communication\Form\Type\ThresholdGroup\GlobalSoftThresholdType;
use Spryker\Zed\SalesOrderThresholdGui\SalesOrderThresholdGuiConfig;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\SalesOrderThresholdGui\Communication\SalesOrderThresholdGuiCommunicationFactory getFactory()
 */
class GlobalController extends AbstractController
{
    protected const PARAM_STORE_CURRENCY_REQUEST = 'store_currency';

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Symfony\Component\HttpFoundation\RedirectResponse|array
     */
    public function indexAction(Request $request)
    {
        $storeCurrencyRequestParam = $request->query->get(static::PARAM_STORE_CURRENCY_REQUEST);

        $currencyTransfer = $this->getCurrencyTransferFromRequest($storeCurrencyRequestParam);
        $storeTransfer = $this->getStoreTransferFromRequest($storeCurrencyRequestParam);

        $globalThresholdForm = $this->getFactory()->createGlobalThresholdForm($storeTransfer, $currencyTransfer);
        $globalThresholdForm->handleRequest($request);

        if ($globalThresholdForm->isSubmitted() && $globalThresholdForm->isValid()) {
            return $this->handleFormSubmission($request, $globalThresholdForm, $storeTransfer, $currencyTransfer);
        }

        $localeCollection = $this->getFactory()
            ->getLocaleFacade()
            ->getLocaleCollection();

        return $this->viewResponse([
            'localeCollection' => $localeCollection,
            'globalThresholdForm' => $globalThresholdForm->createView(),
        ]);
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Symfony\Component\Form\FormInterface $globalThresholdForm
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     * @param \Generated\Shared\Transfer\CurrencyTransfer $currencyTransfer
     *
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    protected function handleFormSubmission(
        Request $request,
        FormInterface $globalThresholdForm,
        StoreTransfer $storeTransfer,
        CurrencyTransfer $currencyTransfer
    ): RedirectResponse {
        $data = $globalThresholdForm->getData();

        $hardSalesOrderThresholdTransfer = $this->createSalesOrderThresholdTransfer(
            $data[GlobalThresholdType::FIELD_HARD][GlobalSoftThresholdType::FIELD_ID_THRESHOLD] ?? null,
            $storeTransfer,
            $currencyTransfer
        );

        if (isset($data[GlobalThresholdType::FIELD_HARD][GlobalHardThresholdType::FIELD_STRATEGY]) &&
            $this->getFactory()->createGlobalSoftThresholdFormMapperResolver()->hasGlobalThresholdMapperByStrategyGroup(
                SalesOrderThresholdGuiConfig::GROUP_HARD
            )) {
            $hardSalesOrderThresholdTransfer = $this->getFactory()
                ->createGlobalSoftThresholdFormMapperResolver()
                ->resolveGlobalThresholdMapperByStrategyGroup(SalesOrderThresholdGuiConfig::GROUP_HARD)
                ->map($data[GlobalThresholdType::FIELD_HARD], $hardSalesOrderThresholdTransfer);
        }

        $this->saveSalesOrderThreshold($hardSalesOrderThresholdTransfer);

        $softSalesOrderThresholdTransfer = $this->createSalesOrderThresholdTransfer(
            $data[GlobalThresholdType::FIELD_SOFT][GlobalSoftThresholdType::FIELD_ID_THRESHOLD] ?? null,
            $storeTransfer,
            $currencyTransfer
        );

        if (isset($data[GlobalThresholdType::FIELD_SOFT][GlobalSoftThresholdType::FIELD_STRATEGY]) &&
            $this->getFactory()->createGlobalSoftThresholdFormMapperResolver()->hasGlobalThresholdMapperByStrategyGroup(
                SalesOrderThresholdGuiConfig::GROUP_SOFT
            )) {
            $softSalesOrderThresholdTransfer = $this->getFactory()
                ->createGlobalSoftThresholdFormMapperResolver()
                ->resolveGlobalThresholdMapperByStrategyGroup(SalesOrderThresholdGuiConfig::GROUP_SOFT)
                ->map($data[GlobalThresholdType::FIELD_SOFT], $softSalesOrderThresholdTransfer);
        }

        $this->saveSalesOrderThreshold($softSalesOrderThresholdTransfer);

        $this->addSuccessMessage(sprintf(
            'The Global Thresholds is saved successfully.'
        ));

        return $this->redirectResponse($request->getRequestUri());
    }

    /**
     * @param \Generated\Shared\Transfer\SalesOrderThresholdTransfer $salesOrderThresholdTransfer
     *
     * @return void
     */
    protected function saveSalesOrderThreshold(SalesOrderThresholdTransfer $salesOrderThresholdTransfer): void
    {
        if (empty($salesOrderThresholdTransfer->getSalesOrderThresholdValue()->getThreshold())) {
            if ($salesOrderThresholdTransfer->getIdSalesOrderThreshold()) {
                $this->getFactory()
                    ->getSalesOrderThresholdFacade()
                    ->deleteSalesOrderThreshold($salesOrderThresholdTransfer);
            }

            return;
        }

        $this->getFactory()
            ->getSalesOrderThresholdFacade()
            ->saveSalesOrderThreshold($salesOrderThresholdTransfer);
    }

    /**
     * @param string|null $storeCurrencyRequestParam
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    protected function getCurrencyTransferFromRequest(?string $storeCurrencyRequestParam): CurrencyTransfer
    {
        return $this->getFactory()
            ->createStoreCurrencyFinder()
            ->getCurrencyTransferFromRequestParam($storeCurrencyRequestParam);
    }

    /**
     * @param string|null $storeCurrencyRequestParam
     *
     * @return \Generated\Shared\Transfer\StoreTransfer
     */
    protected function getStoreTransferFromRequest(?string $storeCurrencyRequestParam): StoreTransfer
    {
        return $this->getFactory()
            ->createStoreCurrencyFinder()
            ->getStoreTransferFromRequestParam($storeCurrencyRequestParam);
    }

    /**
     * @param int|null $idSalesOrderThreshold
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     * @param \Generated\Shared\Transfer\CurrencyTransfer $currencyTransfer
     *
     * @return \Generated\Shared\Transfer\SalesOrderThresholdTransfer
     */
    protected function createSalesOrderThresholdTransfer(
        ?int $idSalesOrderThreshold,
        StoreTransfer $storeTransfer,
        CurrencyTransfer $currencyTransfer
    ): SalesOrderThresholdTransfer {
        return (new SalesOrderThresholdTransfer())
            ->setIdSalesOrderThreshold($idSalesOrderThreshold)
            ->setStore($storeTransfer)
            ->setCurrency($currencyTransfer)
            ->setSalesOrderThresholdValue(new SalesOrderThresholdValueTransfer());
    }
}
