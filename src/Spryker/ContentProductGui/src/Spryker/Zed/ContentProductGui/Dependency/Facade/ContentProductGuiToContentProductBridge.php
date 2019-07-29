<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ContentProductGui\Dependency\Facade;

use Generated\Shared\Transfer\ContentProductAbstractListTermTransfer;
use Generated\Shared\Transfer\ContentValidationResponseTransfer;

class ContentProductGuiToContentProductBridge implements ContentProductGuiToContentProductInterface
{
    /**
     * @var \Spryker\Zed\ContentProduct\Business\ContentProductFacadeInterface
     */
    protected $contentProductFacade;

    /**
     * @param \Spryker\Zed\ContentProduct\Business\ContentProductFacadeInterface $contentProductFacade
     */
    public function __construct($contentProductFacade)
    {
        $this->contentProductFacade = $contentProductFacade;
    }

    /**
     * @param \Generated\Shared\Transfer\ContentProductAbstractListTermTransfer $contentProductAbstractListTermTransfer
     *
     * @return \Generated\Shared\Transfer\ContentValidationResponseTransfer
     */
    public function validateContentProductAbstractListTerm(
        ContentProductAbstractListTermTransfer $contentProductAbstractListTermTransfer
    ): ContentValidationResponseTransfer {
        return $this->contentProductFacade->validateContentProductAbstractListTerm($contentProductAbstractListTermTransfer);
    }
}
