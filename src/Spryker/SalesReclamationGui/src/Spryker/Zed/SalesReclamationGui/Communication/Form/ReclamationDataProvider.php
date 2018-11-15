<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesReclamationGui\Communication\Form;

use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Zed\SalesReclamationGui\Communication\Table\ReclamationTable;
use Symfony\Component\HttpFoundation\Request;

class ReclamationDataProvider
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
     * @return array
     */
    public function getOptions(QuoteTransfer $quoteTransfer): array
    {
        $value = null;

        if (!$quoteTransfer->getReclamationId()
            && $this->request->query->has(ReclamationTable::PARAM_ID_RECLAMATION)
        ) {
            $value = $this->request->query->get(ReclamationTable::PARAM_ID_RECLAMATION);
        }

        return [
            'data_class' => QuoteTransfer::class,
            'allow_extra_fields' => true,
            'csrf_protection' => false,
            ReclamationType::OPTION_VALUE => $value,
        ];
    }
}
