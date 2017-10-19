<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsBlockProductConnector\Dependency\Facade;

class CmsBlockProductConnectorToTouchBridge implements CmsBlockProductConnectorToTouchInterface
{
    /**
     * @var \Spryker\Zed\Touch\Business\TouchFacadeInterface
     */
    protected $touchFacade;

    /**
     * @param \Spryker\Zed\Touch\Business\TouchFacadeInterface $touchFacade
     */
    public function __construct($touchFacade)
    {
        $this->touchFacade = $touchFacade;
    }

    /**
     * @param string $itemType
     * @param int $idCmsBlock
     *
     * @return bool
     */
    public function touchActive($itemType, $idCmsBlock)
    {
        return $this->touchFacade->touchActive($itemType, $idCmsBlock);
    }

    /**
     * @param string $itemType
     * @param int $idCmsBlock
     *
     * @return bool
     */
    public function touchDeleted($itemType, $idCmsBlock)
    {
        return $this->touchFacade->touchDeleted($itemType, $idCmsBlock);
    }
}
