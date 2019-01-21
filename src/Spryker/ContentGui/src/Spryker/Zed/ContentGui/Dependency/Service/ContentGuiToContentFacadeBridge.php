<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ContentGui\Dependency\Service;

use Generated\Shared\Transfer\ContentTransfer;

class ContentGuiToContentFacadeBridge implements ContentGuiToContentFacadeInterface
{
    /**
     * @var \Spryker\Zed\Content\Business\ContentFacadeInterface
     */
    protected $contentFacade;

    /**
     * @param \Spryker\Zed\Content\Business\ContentFacadeInterface $contentFacade
     */
    public function __construct($contentFacade)
    {
        $this->contentFacade = $contentFacade;
    }

    /**
     * @param int $id
     *
     * @return \Generated\Shared\Transfer\ContentTransfer
     */
    public function findContentById(int $id): ContentTransfer
    {
        return $this->contentFacade->findContentById($id);
    }

    /**
     * @param \Generated\Shared\Transfer\ContentTransfer $contentTransfer
     *
     * @return \Generated\Shared\Transfer\ContentTransfer
     */
    public function create(ContentTransfer $contentTransfer): ContentTransfer
    {
        return $this->contentFacade->create($contentTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ContentTransfer $contentTransfer
     *
     * @return \Generated\Shared\Transfer\ContentTransfer
     */
    public function update(ContentTransfer $contentTransfer): ContentTransfer
    {
        return $this->contentFacade->update($contentTransfer);
    }
}
