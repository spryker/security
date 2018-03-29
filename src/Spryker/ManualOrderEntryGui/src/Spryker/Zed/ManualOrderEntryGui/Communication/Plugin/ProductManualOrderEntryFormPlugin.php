<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ManualOrderEntryGui\Communication\Plugin;

use ArrayObject;
use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\ManualOrderProductTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Shared\Kernel\Transfer\AbstractTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\ManualOrderEntryGui\Communication\Form\Product\ProductCollectionType;
use Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Traits\UniqueFlashMessagesTrait;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\ManualOrderEntryGui\Communication\ManualOrderEntryGuiCommunicationFactory getFactory()
 */
class ProductManualOrderEntryFormPlugin extends AbstractPlugin implements ManualOrderEntryFormPluginInterface
{
    use UniqueFlashMessagesTrait;

    /**
     * @var \Spryker\Zed\ManualOrderEntryGui\Dependency\Facade\ManualOrderEntryGuiToCartFacadeInterface
     */
    protected $cartFacade;

    /**
     * @var \Spryker\Zed\ManualOrderEntryGui\Dependency\Facade\ManualOrderEntryGuiToMessengerFacadeInterface
     */
    protected $messengerFacade;

    /**
     * @var \Spryker\Zed\ManualOrderEntryGui\Dependency\Facade\ManualOrderEntryGuiToProductFacadeInterface
     */
    protected $productFacade;

    public function __construct()
    {
        $this->cartFacade = $this->getFactory()->getCartFacade();
        $this->productFacade = $this->getFactory()->getProductFacade();
        $this->messengerFacade = $this->getFactory()->getMessengerFacade();
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return ProductCollectionType::TYPE_NAME;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Spryker\Shared\Kernel\Transfer\AbstractTransfer|null $dataTransfer
     *
     * @return \Symfony\Component\Form\FormInterface
     */
    public function createForm(Request $request, $dataTransfer = null): FormInterface
    {
        return $this->getFactory()->createProductsCollectionForm($dataTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param \Symfony\Component\Form\FormInterface $form
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function handleData($quoteTransfer, &$form, $request): AbstractTransfer
    {
        $cartChangeTransfer = new CartChangeTransfer();
        $addedSkus = [];

        foreach ($quoteTransfer->getManualOrderProducts() as $manualOrderProduct) {
            if (!strlen($manualOrderProduct->getSku())
                || $manualOrderProduct->getQuantity() <= 0
                || in_array($manualOrderProduct->getSku(), $addedSkus)
                || !$this->productFacade->hasProductConcrete($manualOrderProduct->getSku())
            ) {
                continue;
            }

            $addedSkus[] = $manualOrderProduct->getSku();
            $itemTransfer = new ItemTransfer();
            $itemTransfer->fromArray($manualOrderProduct->toArray());

            $cartChangeTransfer->addItem($itemTransfer);
        }
        if (count($cartChangeTransfer->getItems())) {
            $cartChangeTransfer->setQuote($quoteTransfer);
            $quoteTransfer = $this->cartFacade->add($cartChangeTransfer);
        }

        $quoteTransfer = $this->mergeItemsBySku($quoteTransfer);
        $this->updateManualOrderItems($quoteTransfer);

        $form = $this->createForm($request, $quoteTransfer);
        $form->setData($quoteTransfer->toArray());

        $this->uniqueFlashMessages();

        return $quoteTransfer;
    }

    /**
     * @param \Spryker\Shared\Kernel\Transfer\AbstractTransfer|null $dataTransfer
     *
     * @return bool
     */
    public function isPreFilled($dataTransfer = null): bool
    {
        return false;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return void
     */
    protected function updateManualOrderItems($quoteTransfer): void
    {
        foreach ($quoteTransfer->getItems() as $itemTransfer) {
            $manualOrderProductTransfer = new ManualOrderProductTransfer();
            $manualOrderProductTransfer->setSku($itemTransfer->getSku())
                ->setQuantity($itemTransfer->getQuantity())
                ->setUnitGrossPrice($itemTransfer->getUnitGrossPrice());

            $quoteTransfer->addManualOrderItems($manualOrderProductTransfer);
        }
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    protected function mergeItemsBySku($quoteTransfer): QuoteTransfer
    {
        $items = [];
        foreach ($quoteTransfer->getItems() as $itemTransfer) {
            if (isset($items[$itemTransfer->getSku()])) {
                $items[$itemTransfer->getSku()]->setQuantity(
                    $items[$itemTransfer->getSku()]->getQuantity() + $itemTransfer->getQuantity()
                );
                continue;
            }

            $newItemTransfer = new ItemTransfer();
            $newItemTransfer->setSku($itemTransfer->getSku())
                ->setQuantity($itemTransfer->getQuantity())
                ->setUnitGrossPrice($itemTransfer->getUnitGrossPrice())
                ->setForcedUnitGrossPrice(true);

            $items[$itemTransfer->getSku()] = $newItemTransfer;
        }
        $items = new ArrayObject($items);
        $quoteTransfer->setItems($items);
        $quoteTransfer->setBundleItems(new ArrayObject());
        if (count($items)) {
            $quoteTransfer = $this->cartFacade->reloadItems($quoteTransfer);
        }

        return $quoteTransfer;
    }
}
