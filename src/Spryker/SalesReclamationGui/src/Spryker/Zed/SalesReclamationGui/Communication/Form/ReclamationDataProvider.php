<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesReclamationGui\Communication\Form;

use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Zed\ManualOrderEntryGui\Communication\Form\DataProvider\FormDataProviderInterface;
use Spryker\Zed\SalesReclamationGui\SalesReclamationGuiConfig;
use Symfony\Component\HttpFoundation\Request;

class ReclamationDataProvider implements FormDataProviderInterface
{
    /**
     * @var \Symfony\Component\HttpFoundation\Request
     */
    protected $request;

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     */
    public function __construct(
        Request $request
    ) {
        $this->request = $request;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function getData($quoteTransfer): QuoteTransfer
    {
        return $quoteTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return array
     */
    public function getOptions($quoteTransfer): array
    {
        $value = null;

        if (!$quoteTransfer->getReclamationId()
            && $this->request->query->has(SalesReclamationGuiConfig::PARAM_ID_RECLAMATION)
        ) {
            $value = $this->request->query->get(SalesReclamationGuiConfig::PARAM_ID_RECLAMATION);
        }

        return [
            'data_class' => QuoteTransfer::class,
            'allow_extra_fields' => true,
            'csrf_protection' => false,
            ReclamationType::OPTION_VALUE => $value,
        ];
    }
}
