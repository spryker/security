<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsBlock\Business;

use Generated\Shared\Transfer\CmsBlockGlossaryTransfer;
use Generated\Shared\Transfer\CmsBlockTransfer;
use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\CmsBlock\Business\CmsBlockBusinessFactory getFactory()
 */
class CmsBlockFacade extends AbstractFacade implements CmsBlockFacadeInterface
{

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idCmsBlock
     *
     * @return \Generated\Shared\Transfer\CmsBlockTransfer
     */
    public function findCmsBlockById($idCmsBlock)
    {
        return $this->getFactory()
            ->createCmsBlockReader()
            ->findCmsBlockById($idCmsBlock);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idCmsBlock
     *
     * @return void
     */
    public function activateById($idCmsBlock)
    {
        $this->getFactory()
            ->createCmsBlockWrite()
            ->activateById($idCmsBlock);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idCmsBlock
     *
     * @return void
     */
    public function deactivateById($idCmsBlock)
    {
        $this->getFactory()
            ->createCmsBlockWrite()
            ->deactivateById($idCmsBlock);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CmsBlockTransfer $cmsBlockTransfer
     *
     * @throws \Spryker\Zed\CmsBlock\Business\Exception\CmsBlockNotFoundException
     * @throws \Spryker\Zed\CmsBlock\Business\Exception\CmsBlockTemplateNotFoundException
     *
     * @return void
     */
    public function updateCmsBlock(CmsBlockTransfer $cmsBlockTransfer)
    {
        $this->getFactory()
            ->createCmsBlockWrite()
            ->updateCmsBlock($cmsBlockTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CmsBlockTransfer $cmsBlockTransfer
     *
     * @return \Generated\Shared\Transfer\CmsBlockTransfer
     */
    public function createCmsBlock(CmsBlockTransfer $cmsBlockTransfer)
    {
        return $this->getFactory()
            ->createCmsBlockWrite()
            ->createCmsBlock($cmsBlockTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $templatePath
     *
     * @return void
     */
    public function syncTemplate($templatePath)
    {
        $this->getFactory()
            ->createCmsBlockTemplateManager()
            ->syncTemplate($templatePath);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idCmsBlock
     *
     * @return \Generated\Shared\Transfer\CmsBlockGlossaryTransfer
     */
    public function findGlossary($idCmsBlock)
    {
        return $this->getFactory()
            ->createCmsBlockGlossaryManager()
            ->findPlaceholders($idCmsBlock);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CmsBlockGlossaryTransfer $cmsBlockGlossaryTransfer
     *
     * @throws \Spryker\Zed\CmsBlock\Business\Exception\CmsBlockMappingAmbiguousException
     * @throws \Spryker\Zed\CmsBlock\Business\Exception\MissingCmsBlockGlossaryKeyMapping
     *
     * @return \Generated\Shared\Transfer\CmsBlockGlossaryTransfer
     */
    public function saveGlossary(CmsBlockGlossaryTransfer $cmsBlockGlossaryTransfer)
    {
        return $this->getFactory()
            ->createCmsBlockGlossaryWriter()
            ->saveGlossary($cmsBlockGlossaryTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $name
     * @param string $path
     *
     * @return \Generated\Shared\Transfer\CmsBlockTemplateTransfer
     */
    public function createTemplate($name, $path)
    {
        return $this->getFactory()
            ->createCmsBlockTemplateManager()
            ->createTemplate($name, $path);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $path
     *
     * @return \Generated\Shared\Transfer\CmsBlockTemplateTransfer|null
     */
    public function findTemplate($path)
    {
        return $this->getFactory()
            ->createCmsBlockTemplateManager()
            ->findTemplateByPath($path);
    }

    /**
     * @inheritdoc
     *
     * @api
     *
     * @param int $idCmsBlockTemplate
     *
     * @return bool
     */
    public function hasTemplateFileById($idCmsBlockTemplate)
    {
        return $this->getFactory()
            ->createCmsBlockTemplateManager()
            ->hasTemplateFileById($idCmsBlockTemplate);
    }

}
