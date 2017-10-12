<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductLabelGui\Communication\Controller;

use Generated\Shared\Transfer\ProductLabelProductAbstractRelationsTransfer;
use Generated\Shared\Transfer\ProductLabelTransfer;
use Spryker\Zed\Kernel\Communication\Controller\AbstractController;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\ProductLabelGui\Communication\ProductLabelGuiCommunicationFactory getFactory()
 */
class EditController extends AbstractController
{
    const PARAM_ID_PRODUCT_LABEL = 'id-product-label';

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array|\Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function indexAction(Request $request)
    {
        $idProductLabel = $this->castId($request->query->get(static::PARAM_ID_PRODUCT_LABEL));
        $productLabelTransfer = $this->findProductLabelById($idProductLabel);

        $productLabelAggregateForm = $this->createProductLabelAggregateForm($productLabelTransfer);
        $isFormSuccessfullyHandled = $this->handleProductLabelAggregateForm(
            $request,
            $productLabelAggregateForm
        );

        if ($isFormSuccessfullyHandled) {
            return $this->redirectResponse('/product-label-gui');
        }

        return $this->viewResponse([
            'productLabelTransfer' => $productLabelTransfer,
            'productLabelFormTabs' => $this->getFactory()->createProductLabelFormTabs()->createView(),
            'aggregateForm' => $productLabelAggregateForm->createView(),
            'availableProductTable' => $this->getFactory()->createAvailableProductTable($idProductLabel)->render(),
            'assignedProductTable' => $this->getFactory()->createAssignedProductTable($idProductLabel)->render(),
        ]);
    }

    /**
     * @param int $idProductLabel
     *
     * @return \Generated\Shared\Transfer\ProductLabelTransfer|null
     */
    protected function findProductLabelById($idProductLabel)
    {
        return $this
            ->getFactory()
            ->getProductLabelFacade()
            ->findLabelById($idProductLabel);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductLabelTransfer $productLabelTransfer
     *
     * @return \Symfony\Component\Form\FormInterface
     */
    protected function createProductLabelAggregateForm(ProductLabelTransfer $productLabelTransfer)
    {
        $aggregateFormDataProvider = $this
            ->getFactory()
            ->createProductLabelAggregateFormDataProvider();

        $aggregateForm = $this
            ->getFactory()
            ->createProductLabelAggregateForm(
                $aggregateFormDataProvider->getData($productLabelTransfer->getIdProductLabel()),
                $aggregateFormDataProvider->getOptions()
            );

        return $aggregateForm;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Symfony\Component\Form\FormInterface $aggregateForm
     *
     * @return bool
     */
    protected function handleProductLabelAggregateForm(Request $request, FormInterface $aggregateForm)
    {
        $aggregateForm->handleRequest($request);

        if (!$aggregateForm->isValid()) {
            return false;
        }

        /** @var \Generated\Shared\Transfer\ProductLabelAggregateFormTransfer $aggregateFormTransfer */
        $aggregateFormTransfer = $aggregateForm->getData();

        $productLabelTransfer = $this->storeProductLabel($aggregateFormTransfer->getProductLabel());
        if (!$productLabelTransfer->getIsDynamic()) {
            $this->storeRelatedProduct($aggregateFormTransfer->getProductAbstractRelations());
        }

        $this->addSuccessMessage(sprintf(
            'Product label #%d successfully updated.',
            $productLabelTransfer->getIdProductLabel()
        ));

        return true;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductLabelTransfer $productLabelTransfer
     *
     * @return \Generated\Shared\Transfer\ProductLabelTransfer
     */
    protected function storeProductLabel(ProductLabelTransfer $productLabelTransfer)
    {
        $this
            ->getFactory()
            ->getProductLabelFacade()
            ->updateLabel($productLabelTransfer);

        return $productLabelTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductLabelProductAbstractRelationsTransfer $relationsTransfer
     *
     * @return void
     */
    protected function storeRelatedProduct(ProductLabelProductAbstractRelationsTransfer $relationsTransfer)
    {
        $this->storeNewProductRelations($relationsTransfer);
        $this->storeRemovedProductRelations($relationsTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductLabelProductAbstractRelationsTransfer $relationsTransfer
     *
     * @return void
     */
    protected function storeNewProductRelations(ProductLabelProductAbstractRelationsTransfer $relationsTransfer)
    {
        if (!count($relationsTransfer->getIdsProductAbstractToAssign())) {
            return;
        }

        $this
            ->getFactory()
            ->getProductLabelFacade()
            ->addAbstractProductRelationsForLabel(
                $relationsTransfer->getIdProductLabel(),
                $relationsTransfer->getIdsProductAbstractToAssign()
            );
    }

    /**
     * @param \Generated\Shared\Transfer\ProductLabelProductAbstractRelationsTransfer $relationsTransfer
     *
     * @return void
     */
    protected function storeRemovedProductRelations(ProductLabelProductAbstractRelationsTransfer $relationsTransfer)
    {
        if (!count($relationsTransfer->getIdsProductAbstractToDeAssign())) {
            return;
        }

        $this
            ->getFactory()
            ->getProductLabelFacade()
            ->removeAbstractProductRelationsForLabel(
                $relationsTransfer->getIdProductLabel(),
                $relationsTransfer->getIdsProductAbstractToDeAssign()
            );
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Symfony\Component\HttpFoundation\JsonResponse
     */
    public function availableProductTableAction(Request $request)
    {
        $idProductLabel = $this->castId($request->query->get(static::PARAM_ID_PRODUCT_LABEL));
        $availableProductTable = $this->getFactory()->createAvailableProductTable($idProductLabel);

        return $this->jsonResponse($availableProductTable->fetchData());
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Symfony\Component\HttpFoundation\JsonResponse
     */
    public function assignedProductTableAction(Request $request)
    {
        $idProductLabel = $this->castId($request->query->get(static::PARAM_ID_PRODUCT_LABEL));
        $assignedProductTable = $this->getFactory()->createAssignedProductTable($idProductLabel);

        return $this->jsonResponse($assignedProductTable->fetchData());
    }
}
