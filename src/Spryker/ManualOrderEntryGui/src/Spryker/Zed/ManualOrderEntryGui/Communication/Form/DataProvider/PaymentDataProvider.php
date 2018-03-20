<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ManualOrderEntryGui\Communication\Form\DataProvider;

use Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment\SubFormInterface;

class PaymentDataProvider implements FormDataProviderInterface
{

    /**
     * @var \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment\SubFormPluginCollection
     */
    protected $subFormPlugins;

    /**
     * @param \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment\SubFormPluginCollection $subFormPlugins
     */
    public function __construct($subFormPlugins)
    {
        $this->subFormPlugins = $subFormPlugins;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return array
     */
    public function getOptions($quoteTransfer)
    {
        $options = [];
        foreach ($this->subFormPlugins as $subForm) {
            $options = array_merge(
                $options,
                $subForm->createSubFormDataProvider()->getOptions($quoteTransfer)
            );
        }

        return [
            'allow_extra_fields' => true,
            'csrf_protection' => false,
            SubFormInterface::OPTIONS_FIELD_NAME => $options,
        ];
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function getData($quoteTransfer)
    {
        foreach ($this->subFormPlugins as $subForm) {
            $quoteTransfer = $subForm->createSubFormDataProvider()->getData($quoteTransfer);
        }

        return $quoteTransfer;
    }

}
