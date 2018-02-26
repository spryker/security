<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsBlockGui\Communication\Controller;

use ArrayObject;
use Generated\Shared\Transfer\StoreTransfer;
use Spryker\Service\UtilText\Model\Url\Url;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\CmsBlockGui\Communication\CmsBlockGuiCommunicationFactory getFactory()
 */
class ViewBlockController extends AbstractBlockController
{
    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array|\Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function indexAction(Request $request)
    {
        $cmsBlockTransfer = $this->findCmsBlockById($request);

        if ($cmsBlockTransfer === null) {
            $this->addErrorMessage(static::MESSAGE_CMS_BLOCK_INVALID_ID_ERROR);
            $redirectUrl = Url::generate('/cms-block-gui/list-block')->build();

            return $this->redirectResponse($redirectUrl);
        }

        $cmsBlockGlossary = $this
            ->getFactory()
            ->getCmsBlockFacade()
            ->findGlossary($cmsBlockTransfer->getIdCmsBlock());

        $relatedStoreNames = $this->getStoreNames($cmsBlockTransfer->getStoreRelation()->getStores());

        return $this->viewResponse([
            'cmsBlock' => $cmsBlockTransfer,
            'cmsBlockGlossary' => $cmsBlockGlossary,
            'renderedPlugins' => $this->getRenderedViewPlugins($cmsBlockTransfer->getIdCmsBlock()),
            'relatedStoreNames' => $relatedStoreNames,
        ]);
    }

    /**
     * @param int $idCmsBlock
     *
     * @return string[]
     */
    protected function getRenderedViewPlugins($idCmsBlock)
    {
        $viewPlugins = $this->getFactory()
            ->getCmsBlockViewPlugins();

        $currentLocale = $this->getFactory()
            ->getLocaleFacade()
            ->getCurrentLocale();

        $viewRenderedPlugins = [];

        foreach ($viewPlugins as $viewPlugin) {
            $viewRenderedPlugins[$viewPlugin->getName()] =
                $viewPlugin->getRenderedList($idCmsBlock, $currentLocale->getIdLocale());
        }

        return $viewRenderedPlugins;
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\StoreTransfer[] $stores
     *
     * @return string[]
     */
    protected function getStoreNames(ArrayObject $stores)
    {
        return array_map(function (StoreTransfer $storeTransfer) {
            return $storeTransfer->getName();
        }, $stores->getArrayCopy());
    }
}
