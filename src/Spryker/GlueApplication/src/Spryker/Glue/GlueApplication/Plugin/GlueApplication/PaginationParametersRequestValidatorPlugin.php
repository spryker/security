<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\GlueApplication\Plugin\GlueApplication;

use Generated\Shared\Transfer\RestErrorMessageTransfer;
use Spryker\Glue\GlueApplicationExtension\Dependency\Plugin\ValidateHttpRequestPluginInterface;
use Spryker\Glue\Kernel\AbstractPlugin;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Glue\GlueApplication\GlueApplicationFactory getFactory()
 */
class PaginationParametersRequestValidatorPlugin extends AbstractPlugin implements ValidateHttpRequestPluginInterface
{
    /**
     * {@inheritdoc}
     *  - Validates pagination parameters of request.
     *  - Return error if parameters are invalid.
     *
     * @api
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Generated\Shared\Transfer\RestErrorMessageTransfer|null
     */
    public function validate(Request $request): ?RestErrorMessageTransfer
    {
        return $this->getFactory()
            ->createPaginationParametersRequestValidator()
            ->validate($request);
    }
}
