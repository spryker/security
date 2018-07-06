<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\SearchRestApi\Processor\Catalog;

use Generated\Shared\Transfer\RestSearchRequestAttributesTransfer;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface;

interface CatalogReaderInterface
{
    /**
     * @param \Generated\Shared\Transfer\RestSearchRequestAttributesTransfer $restSearchRequestAttributesTransfer
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    public function catalogSearch(RestSearchRequestAttributesTransfer $restSearchRequestAttributesTransfer): RestResponseInterface;
}
