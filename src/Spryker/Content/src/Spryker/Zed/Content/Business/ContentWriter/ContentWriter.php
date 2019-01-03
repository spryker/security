<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Content\Business\ContentWriter;

use Generated\Shared\Transfer\ContentTransfer;
use Spryker\Zed\Content\Persistence\ContentEntityManagerInterface;

class ContentWriter implements ContentWriterInterface
{
    /**
     * @var \Spryker\Zed\Content\Persistence\ContentEntityManagerInterface
     */
    protected $contentEntityManager;

    /**
     * @param \Spryker\Zed\Content\Persistence\ContentEntityManagerInterface $contentEntityManager
     */
    public function __construct(ContentEntityManagerInterface $contentEntityManager)
    {
        $this->contentEntityManager = $contentEntityManager;
    }

    /**
     * @param \Generated\Shared\Transfer\ContentTransfer $contentTransfer
     *
     * @return \Generated\Shared\Transfer\ContentTransfer
     */
    public function create(ContentTransfer $contentTransfer): ContentTransfer
    {
        return $this->contentEntityManager->saveContent($contentTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ContentTransfer $contentTransfer
     *
     * @return \Generated\Shared\Transfer\ContentTransfer
     */
    public function update(ContentTransfer $contentTransfer): ContentTransfer
    {
        $contentTransfer
            ->requireIdContent()
            ->requireName();

        return $this->contentEntityManager->saveContent($contentTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ContentTransfer $contentTransfer
     *
     * @return void
     */
    public function delete(ContentTransfer $contentTransfer): void
    {
        $this->contentEntityManager->delete($contentTransfer);
    }
}
